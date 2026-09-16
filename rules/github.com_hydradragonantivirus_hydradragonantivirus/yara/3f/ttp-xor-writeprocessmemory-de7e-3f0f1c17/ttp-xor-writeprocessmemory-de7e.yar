rule TTP_XOR_WriteProcessMemory_de7e {
  strings:
    $key_de7e = { 89 0c [2] bb 2e [2] bd 1b [2] 93 1b [2] ac 07 }

  condition:
    any of them
}