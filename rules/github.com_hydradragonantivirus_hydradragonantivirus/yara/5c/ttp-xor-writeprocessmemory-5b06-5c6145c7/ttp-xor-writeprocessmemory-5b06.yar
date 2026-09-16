rule TTP_XOR_WriteProcessMemory_5b06 {
  strings:
    $key_5b06 = { 0c 74 [2] 3e 56 [2] 38 63 [2] 16 63 [2] 29 7f }

  condition:
    any of them
}