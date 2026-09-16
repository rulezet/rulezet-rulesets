rule TTP_XOR_WriteProcessMemory_5036 {
  strings:
    $key_5036 = { 07 44 [2] 35 66 [2] 33 53 [2] 1d 53 [2] 22 4f }

  condition:
    any of them
}