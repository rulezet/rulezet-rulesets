rule TTP_XOR_WriteProcessMemory_d89d {
  strings:
    $key_d89d = { 8f ef [2] bd cd [2] bb f8 [2] 95 f8 [2] aa e4 }

  condition:
    any of them
}