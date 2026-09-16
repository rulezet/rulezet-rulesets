rule TTP_XOR_WriteProcessMemory_ce9d {
  strings:
    $key_ce9d = { 99 ef [2] ab cd [2] ad f8 [2] 83 f8 [2] bc e4 }

  condition:
    any of them
}