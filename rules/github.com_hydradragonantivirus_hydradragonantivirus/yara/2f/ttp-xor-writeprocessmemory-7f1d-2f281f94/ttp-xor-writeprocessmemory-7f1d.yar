rule TTP_XOR_WriteProcessMemory_7f1d {
  strings:
    $key_7f1d = { 28 6f [2] 1a 4d [2] 1c 78 [2] 32 78 [2] 0d 64 }

  condition:
    any of them
}