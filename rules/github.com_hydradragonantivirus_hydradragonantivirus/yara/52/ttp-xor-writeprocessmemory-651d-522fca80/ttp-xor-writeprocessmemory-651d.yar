rule TTP_XOR_WriteProcessMemory_651d {
  strings:
    $key_651d = { 32 6f [2] 00 4d [2] 06 78 [2] 28 78 [2] 17 64 }

  condition:
    any of them
}