rule TTP_XOR_WriteProcessMemory_de59 {
  strings:
    $key_de59 = { 89 2b [2] bb 09 [2] bd 3c [2] 93 3c [2] ac 20 }

  condition:
    any of them
}