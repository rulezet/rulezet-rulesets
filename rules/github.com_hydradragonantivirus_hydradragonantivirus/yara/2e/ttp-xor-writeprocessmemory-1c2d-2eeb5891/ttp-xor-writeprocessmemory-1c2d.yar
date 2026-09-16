rule TTP_XOR_WriteProcessMemory_1c2d {
  strings:
    $key_1c2d = { 4b 5f [2] 79 7d [2] 7f 48 [2] 51 48 [2] 6e 54 }

  condition:
    any of them
}