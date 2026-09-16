rule TTP_XOR_WriteProcessMemory_759d {
  strings:
    $key_759d = { 22 ef [2] 10 cd [2] 16 f8 [2] 38 f8 [2] 07 e4 }

  condition:
    any of them
}