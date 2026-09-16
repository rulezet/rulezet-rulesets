rule TTP_XOR_WriteProcessMemory_1c3d {
  strings:
    $key_1c3d = { 4b 4f [2] 79 6d [2] 7f 58 [2] 51 58 [2] 6e 44 }

  condition:
    any of them
}