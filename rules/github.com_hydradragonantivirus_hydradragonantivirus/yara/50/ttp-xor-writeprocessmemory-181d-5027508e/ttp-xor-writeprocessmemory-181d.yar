rule TTP_XOR_WriteProcessMemory_181d {
  strings:
    $key_181d = { 4f 6f [2] 7d 4d [2] 7b 78 [2] 55 78 [2] 6a 64 }

  condition:
    any of them
}