rule TTP_XOR_WriteProcessMemory_339d {
  strings:
    $key_339d = { 64 ef [2] 56 cd [2] 50 f8 [2] 7e f8 [2] 41 e4 }

  condition:
    any of them
}