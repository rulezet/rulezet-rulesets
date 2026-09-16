rule TTP_XOR_WriteProcessMemory_de9d {
  strings:
    $key_de9d = { 89 ef [2] bb cd [2] bd f8 [2] 93 f8 [2] ac e4 }

  condition:
    any of them
}