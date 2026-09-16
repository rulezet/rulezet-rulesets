rule TTP_XOR_WriteProcessMemory_4dbf {
  strings:
    $key_4dbf = { 1a cd [2] 28 ef [2] 2e da [2] 00 da [2] 3f c6 }

  condition:
    any of them
}