rule TTP_XOR_WriteProcessMemory_8ae8 {
  strings:
    $key_8ae8 = { dd 9a [2] ef b8 [2] e9 8d [2] c7 8d [2] f8 91 }

  condition:
    any of them
}