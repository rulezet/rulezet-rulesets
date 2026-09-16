rule TTP_XOR_WriteProcessMemory_969d {
  strings:
    $key_969d = { c1 ef [2] f3 cd [2] f5 f8 [2] db f8 [2] e4 e4 }

  condition:
    any of them
}