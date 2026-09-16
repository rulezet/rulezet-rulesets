rule TTP_XOR_WriteProcessMemory_2403 {
  strings:
    $key_2403 = { 73 71 [2] 41 53 [2] 47 66 [2] 69 66 [2] 56 7a }

  condition:
    any of them
}