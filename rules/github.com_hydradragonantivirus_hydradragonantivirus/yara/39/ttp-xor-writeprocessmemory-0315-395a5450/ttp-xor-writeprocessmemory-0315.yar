rule TTP_XOR_WriteProcessMemory_0315 {
  strings:
    $key_0315 = { 54 67 [2] 66 45 [2] 60 70 [2] 4e 70 [2] 71 6c }

  condition:
    any of them
}