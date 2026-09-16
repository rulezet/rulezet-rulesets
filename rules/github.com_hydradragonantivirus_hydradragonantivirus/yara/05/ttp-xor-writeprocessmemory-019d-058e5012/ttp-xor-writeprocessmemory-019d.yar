rule TTP_XOR_WriteProcessMemory_019d {
  strings:
    $key_019d = { 56 ef [2] 64 cd [2] 62 f8 [2] 4c f8 [2] 73 e4 }

  condition:
    any of them
}