rule TTP_XOR_WriteProcessMemory_2536 {
  strings:
    $key_2536 = { 72 44 [2] 40 66 [2] 46 53 [2] 68 53 [2] 57 4f }

  condition:
    any of them
}