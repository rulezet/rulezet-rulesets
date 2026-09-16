rule TTP_XOR_WriteProcessMemory_6f1d {
  strings:
    $key_6f1d = { 38 6f [2] 0a 4d [2] 0c 78 [2] 22 78 [2] 1d 64 }

  condition:
    any of them
}