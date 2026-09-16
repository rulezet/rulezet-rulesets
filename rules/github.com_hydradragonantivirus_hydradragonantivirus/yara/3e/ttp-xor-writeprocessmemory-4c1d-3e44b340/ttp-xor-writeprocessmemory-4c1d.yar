rule TTP_XOR_WriteProcessMemory_4c1d {
  strings:
    $key_4c1d = { 1b 6f [2] 29 4d [2] 2f 78 [2] 01 78 [2] 3e 64 }

  condition:
    any of them
}