rule TTP_XOR_WriteProcessMemory_0c76 {
  strings:
    $key_0c76 = { 5b 04 [2] 69 26 [2] 6f 13 [2] 41 13 [2] 7e 0f }

  condition:
    any of them
}