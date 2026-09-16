rule TTP_XOR_WriteProcessMemory_7c76 {
  strings:
    $key_7c76 = { 2b 04 [2] 19 26 [2] 1f 13 [2] 31 13 [2] 0e 0f }

  condition:
    any of them
}