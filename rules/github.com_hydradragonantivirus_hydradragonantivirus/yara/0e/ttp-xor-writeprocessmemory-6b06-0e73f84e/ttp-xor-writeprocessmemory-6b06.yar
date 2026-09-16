rule TTP_XOR_WriteProcessMemory_6b06 {
  strings:
    $key_6b06 = { 3c 74 [2] 0e 56 [2] 08 63 [2] 26 63 [2] 19 7f }

  condition:
    any of them
}