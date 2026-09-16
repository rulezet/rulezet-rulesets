rule TTP_XOR_WriteProcessMemory_2f1d {
  strings:
    $key_2f1d = { 78 6f [2] 4a 4d [2] 4c 78 [2] 62 78 [2] 5d 64 }

  condition:
    any of them
}