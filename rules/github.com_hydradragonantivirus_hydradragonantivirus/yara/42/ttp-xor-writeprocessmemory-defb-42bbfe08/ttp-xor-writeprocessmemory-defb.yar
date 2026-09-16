rule TTP_XOR_WriteProcessMemory_defb {
  strings:
    $key_defb = { 89 89 [2] bb ab [2] bd 9e [2] 93 9e [2] ac 82 }

  condition:
    any of them
}