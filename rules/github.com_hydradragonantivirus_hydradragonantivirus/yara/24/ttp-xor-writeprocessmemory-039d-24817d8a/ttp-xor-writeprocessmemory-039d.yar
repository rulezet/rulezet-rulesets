rule TTP_XOR_WriteProcessMemory_039d {
  strings:
    $key_039d = { 54 ef [2] 66 cd [2] 60 f8 [2] 4e f8 [2] 71 e4 }

  condition:
    any of them
}