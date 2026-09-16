rule TTP_XOR_WriteProcessMemory_519d {
  strings:
    $key_519d = { 06 ef [2] 34 cd [2] 32 f8 [2] 1c f8 [2] 23 e4 }

  condition:
    any of them
}