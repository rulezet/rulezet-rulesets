rule TTP_XOR_WriteProcessMemory_4c3d {
  strings:
    $key_4c3d = { 1b 4f [2] 29 6d [2] 2f 58 [2] 01 58 [2] 3e 44 }

  condition:
    any of them
}