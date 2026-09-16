rule TTP_XOR_WriteProcessMemory_619d {
  strings:
    $key_619d = { 36 ef [2] 04 cd [2] 02 f8 [2] 2c f8 [2] 13 e4 }

  condition:
    any of them
}