rule TTP_XOR_WriteProcessMemory_0aa9 {
  strings:
    $key_0aa9 = { 5d db [2] 6f f9 [2] 69 cc [2] 47 cc [2] 78 d0 }

  condition:
    any of them
}