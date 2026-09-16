rule TTP_XOR_WriteProcessMemory_196d {
  strings:
    $key_196d = { 4e 1f [2] 7c 3d [2] 7a 08 [2] 54 08 [2] 6b 14 }

  condition:
    any of them
}