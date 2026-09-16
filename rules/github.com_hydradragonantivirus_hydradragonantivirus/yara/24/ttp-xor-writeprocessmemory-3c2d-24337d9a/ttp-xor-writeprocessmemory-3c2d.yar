rule TTP_XOR_WriteProcessMemory_3c2d {
  strings:
    $key_3c2d = { 6b 5f [2] 59 7d [2] 5f 48 [2] 71 48 [2] 4e 54 }

  condition:
    any of them
}