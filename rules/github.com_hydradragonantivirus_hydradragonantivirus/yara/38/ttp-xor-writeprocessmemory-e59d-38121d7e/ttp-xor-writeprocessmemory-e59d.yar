rule TTP_XOR_WriteProcessMemory_e59d {
  strings:
    $key_e59d = { b2 ef [2] 80 cd [2] 86 f8 [2] a8 f8 [2] 97 e4 }

  condition:
    any of them
}