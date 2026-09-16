rule TTP_XOR_WriteProcessMemory_de09 {
  strings:
    $key_de09 = { 89 7b [2] bb 59 [2] bd 6c [2] 93 6c [2] ac 70 }

  condition:
    any of them
}