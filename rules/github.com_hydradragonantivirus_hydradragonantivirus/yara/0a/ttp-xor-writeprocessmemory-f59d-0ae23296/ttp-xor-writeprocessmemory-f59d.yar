rule TTP_XOR_WriteProcessMemory_f59d {
  strings:
    $key_f59d = { a2 ef [2] 90 cd [2] 96 f8 [2] b8 f8 [2] 87 e4 }

  condition:
    any of them
}