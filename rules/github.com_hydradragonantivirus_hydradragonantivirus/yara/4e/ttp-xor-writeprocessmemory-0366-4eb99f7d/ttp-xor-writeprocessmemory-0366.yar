rule TTP_XOR_WriteProcessMemory_0366 {
  strings:
    $key_0366 = { 54 14 [2] 66 36 [2] 60 03 [2] 4e 03 [2] 71 1f }

  condition:
    any of them
}