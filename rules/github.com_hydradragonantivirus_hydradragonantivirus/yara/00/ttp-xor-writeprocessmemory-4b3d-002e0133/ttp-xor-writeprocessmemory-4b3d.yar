rule TTP_XOR_WriteProcessMemory_4b3d {
  strings:
    $key_4b3d = { 1c 4f [2] 2e 6d [2] 28 58 [2] 06 58 [2] 39 44 }

  condition:
    any of them
}