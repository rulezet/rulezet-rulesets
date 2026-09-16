rule TTP_XOR_WriteProcessMemory_221d {
  strings:
    $key_221d = { 75 6f [2] 47 4d [2] 41 78 [2] 6f 78 [2] 50 64 }

  condition:
    any of them
}