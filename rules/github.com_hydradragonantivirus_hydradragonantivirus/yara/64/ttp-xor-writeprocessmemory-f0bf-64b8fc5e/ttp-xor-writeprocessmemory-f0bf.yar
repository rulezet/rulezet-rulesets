rule TTP_XOR_WriteProcessMemory_f0bf {
  strings:
    $key_f0bf = { a7 cd [2] 95 ef [2] 93 da [2] bd da [2] 82 c6 }

  condition:
    any of them
}