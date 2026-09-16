rule TTP_XOR_WriteProcessMemory_a29d {
  strings:
    $key_a29d = { f5 ef [2] c7 cd [2] c1 f8 [2] ef f8 [2] d0 e4 }

  condition:
    any of them
}