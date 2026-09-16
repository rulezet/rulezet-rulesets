rule TTP_XOR_WriteProcessMemory_5d6d {
  strings:
    $key_5d6d = { 0a 1f [2] 38 3d [2] 3e 08 [2] 10 08 [2] 2f 14 }

  condition:
    any of them
}