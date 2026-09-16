rule TTP_XOR_WriteProcessMemory_bee5 {
  strings:
    $key_bee5 = { e9 97 [2] db b5 [2] dd 80 [2] f3 80 [2] cc 9c }

  condition:
    any of them
}