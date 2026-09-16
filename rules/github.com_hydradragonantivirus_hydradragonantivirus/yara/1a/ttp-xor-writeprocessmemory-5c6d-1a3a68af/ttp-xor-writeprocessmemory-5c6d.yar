rule TTP_XOR_WriteProcessMemory_5c6d {
  strings:
    $key_5c6d = { 0b 1f [2] 39 3d [2] 3f 08 [2] 11 08 [2] 2e 14 }

  condition:
    any of them
}