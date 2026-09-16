rule TTP_XOR_WriteProcessMemory_6c1d {
  strings:
    $key_6c1d = { 3b 6f [2] 09 4d [2] 0f 78 [2] 21 78 [2] 1e 64 }

  condition:
    any of them
}