rule TTP_XOR_WriteProcessMemory_ef9d {
  strings:
    $key_ef9d = { b8 ef [2] 8a cd [2] 8c f8 [2] a2 f8 [2] 9d e4 }

  condition:
    any of them
}