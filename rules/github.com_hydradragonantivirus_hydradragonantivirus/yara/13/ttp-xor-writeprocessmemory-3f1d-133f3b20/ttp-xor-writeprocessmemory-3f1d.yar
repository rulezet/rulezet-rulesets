rule TTP_XOR_WriteProcessMemory_3f1d {
  strings:
    $key_3f1d = { 68 6f [2] 5a 4d [2] 5c 78 [2] 72 78 [2] 4d 64 }

  condition:
    any of them
}