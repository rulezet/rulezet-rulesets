rule TTP_XOR_WriteProcessMemory_1f1d {
  strings:
    $key_1f1d = { 48 6f [2] 7a 4d [2] 7c 78 [2] 52 78 [2] 6d 64 }

  condition:
    any of them
}