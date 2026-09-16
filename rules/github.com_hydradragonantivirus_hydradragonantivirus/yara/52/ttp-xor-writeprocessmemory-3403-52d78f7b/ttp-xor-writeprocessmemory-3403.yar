rule TTP_XOR_WriteProcessMemory_3403 {
  strings:
    $key_3403 = { 63 71 [2] 51 53 [2] 57 66 [2] 79 66 [2] 46 7a }

  condition:
    any of them
}