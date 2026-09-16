rule TTP_XOR_WriteProcessMemory_3b1d {
  strings:
    $key_3b1d = { 6c 6f [2] 5e 4d [2] 58 78 [2] 76 78 [2] 49 64 }

  condition:
    any of them
}