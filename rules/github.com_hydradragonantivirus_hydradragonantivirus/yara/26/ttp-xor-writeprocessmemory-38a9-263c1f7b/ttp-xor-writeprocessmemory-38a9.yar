rule TTP_XOR_WriteProcessMemory_38a9 {
  strings:
    $key_38a9 = { 6f db [2] 5d f9 [2] 5b cc [2] 75 cc [2] 4a d0 }

  condition:
    any of them
}