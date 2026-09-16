rule TTP_XOR_WriteProcessMemory_deec {
  strings:
    $key_deec = { 89 9e [2] bb bc [2] bd 89 [2] 93 89 [2] ac 95 }

  condition:
    any of them
}