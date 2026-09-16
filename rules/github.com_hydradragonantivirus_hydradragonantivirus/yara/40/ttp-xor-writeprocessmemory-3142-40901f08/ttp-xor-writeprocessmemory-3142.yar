rule TTP_XOR_WriteProcessMemory_3142 {
  strings:
    $key_3142 = { 66 30 [2] 54 12 [2] 52 27 [2] 7c 27 [2] 43 3b }

  condition:
    any of them
}