rule TTP_XOR_WriteProcessMemory_810d {
  strings:
    $key_810d = { d6 7f [2] e4 5d [2] e2 68 [2] cc 68 [2] f3 74 }

  condition:
    any of them
}