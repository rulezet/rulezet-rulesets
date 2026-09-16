rule TTP_XOR_WriteProcessMemory_7514 {
  strings:
    $key_7514 = { 22 66 [2] 10 44 [2] 16 71 [2] 38 71 [2] 07 6d }

  condition:
    any of them
}