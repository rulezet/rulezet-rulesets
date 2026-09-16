rule TTP_XOR_WriteProcessMemory_5aa9 {
  strings:
    $key_5aa9 = { 0d db [2] 3f f9 [2] 39 cc [2] 17 cc [2] 28 d0 }

  condition:
    any of them
}