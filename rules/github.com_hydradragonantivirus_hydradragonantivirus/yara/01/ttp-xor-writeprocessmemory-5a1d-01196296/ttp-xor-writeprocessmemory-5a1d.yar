rule TTP_XOR_WriteProcessMemory_5a1d {
  strings:
    $key_5a1d = { 0d 6f [2] 3f 4d [2] 39 78 [2] 17 78 [2] 28 64 }

  condition:
    any of them
}