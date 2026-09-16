rule TTP_XOR_WriteProcessMemory_0332 {
  strings:
    $key_0332 = { 54 40 [2] 66 62 [2] 60 57 [2] 4e 57 [2] 71 4b }

  condition:
    any of them
}