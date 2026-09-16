rule TTP_XOR_WriteProcessMemory_089d {
  strings:
    $key_089d = { 5f ef [2] 6d cd [2] 6b f8 [2] 45 f8 [2] 7a e4 }

  condition:
    any of them
}