rule TTP_XOR_WriteProcessMemory_386d {
  strings:
    $key_386d = { 6f 1f [2] 5d 3d [2] 5b 08 [2] 75 08 [2] 4a 14 }

  condition:
    any of them
}