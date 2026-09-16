rule TTP_XOR_WriteProcessMemory_166d {
  strings:
    $key_166d = { 41 1f [2] 73 3d [2] 75 08 [2] 5b 08 [2] 64 14 }

  condition:
    any of them
}