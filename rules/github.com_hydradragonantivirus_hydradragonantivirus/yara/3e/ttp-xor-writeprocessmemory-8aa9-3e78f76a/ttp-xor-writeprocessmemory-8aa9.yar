rule TTP_XOR_WriteProcessMemory_8aa9 {
  strings:
    $key_8aa9 = { dd db [2] ef f9 [2] e9 cc [2] c7 cc [2] f8 d0 }

  condition:
    any of them
}