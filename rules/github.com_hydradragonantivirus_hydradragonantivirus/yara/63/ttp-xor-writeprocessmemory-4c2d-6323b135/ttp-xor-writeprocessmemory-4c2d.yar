rule TTP_XOR_WriteProcessMemory_4c2d {
  strings:
    $key_4c2d = { 1b 5f [2] 29 7d [2] 2f 48 [2] 01 48 [2] 3e 54 }

  condition:
    any of them
}