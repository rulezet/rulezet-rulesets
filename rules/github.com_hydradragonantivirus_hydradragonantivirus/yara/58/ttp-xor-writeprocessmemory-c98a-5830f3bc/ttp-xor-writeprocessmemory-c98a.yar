rule TTP_XOR_WriteProcessMemory_c98a {
  strings:
    $key_c98a = { 9e f8 [2] ac da [2] aa ef [2] 84 ef [2] bb f3 }

  condition:
    any of them
}