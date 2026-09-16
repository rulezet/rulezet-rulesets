rule TTP_XOR_WriteProcessMemory_de8a {
  strings:
    $key_de8a = { 89 f8 [2] bb da [2] bd ef [2] 93 ef [2] ac f3 }

  condition:
    any of them
}