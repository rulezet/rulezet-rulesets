rule TTP_XOR_WriteProcessMemory_6c76 {
  strings:
    $key_6c76 = { 3b 04 [2] 09 26 [2] 0f 13 [2] 21 13 [2] 1e 0f }

  condition:
    any of them
}