rule TTP_XOR_WriteProcessMemory_28a9 {
  strings:
    $key_28a9 = { 7f db [2] 4d f9 [2] 4b cc [2] 65 cc [2] 5a d0 }

  condition:
    any of them
}