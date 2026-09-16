rule TTP_XOR_WriteProcessMemory_deeb {
  strings:
    $key_deeb = { 89 99 [2] bb bb [2] bd 8e [2] 93 8e [2] ac 92 }

  condition:
    any of them
}