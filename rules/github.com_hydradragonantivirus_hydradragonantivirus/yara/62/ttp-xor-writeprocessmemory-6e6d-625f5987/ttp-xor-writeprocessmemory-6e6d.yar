rule TTP_XOR_WriteProcessMemory_6e6d {
  strings:
    $key_6e6d = { 39 1f [2] 0b 3d [2] 0d 08 [2] 23 08 [2] 1c 14 }

  condition:
    any of them
}