rule TTP_XOR_WriteProcessMemory_689d {
  strings:
    $key_689d = { 3f ef [2] 0d cd [2] 0b f8 [2] 25 f8 [2] 1a e4 }

  condition:
    any of them
}