rule TTP_XOR_WriteProcessMemory_73bf {
  strings:
    $key_73bf = { 24 cd [2] 16 ef [2] 10 da [2] 3e da [2] 01 c6 }

  condition:
    any of them
}