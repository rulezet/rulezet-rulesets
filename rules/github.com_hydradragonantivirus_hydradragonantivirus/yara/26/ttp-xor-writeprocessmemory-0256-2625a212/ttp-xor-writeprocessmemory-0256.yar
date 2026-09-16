rule TTP_XOR_WriteProcessMemory_0256 {
  strings:
    $key_0256 = { 55 24 [2] 67 06 [2] 61 33 [2] 4f 33 [2] 70 2f }

  condition:
    any of them
}