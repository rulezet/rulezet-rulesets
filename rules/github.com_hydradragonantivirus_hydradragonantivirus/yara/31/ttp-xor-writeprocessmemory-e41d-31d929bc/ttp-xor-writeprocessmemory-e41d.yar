rule TTP_XOR_WriteProcessMemory_e41d {
  strings:
    $key_e41d = { b3 6f [2] 81 4d [2] 87 78 [2] a9 78 [2] 96 64 }

  condition:
    any of them
}