rule TTP_XOR_WriteProcessMemory_2a1d {
  strings:
    $key_2a1d = { 7d 6f [2] 4f 4d [2] 49 78 [2] 67 78 [2] 58 64 }

  condition:
    any of them
}