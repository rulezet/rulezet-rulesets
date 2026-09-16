rule TTP_XOR_WriteProcessMemory_bee3 {
  strings:
    $key_bee3 = { e9 91 [2] db b3 [2] dd 86 [2] f3 86 [2] cc 9a }

  condition:
    any of them
}