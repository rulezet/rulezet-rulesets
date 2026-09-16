rule TTP_XOR_WriteProcessMemory_7f6d {
  strings:
    $key_7f6d = { 28 1f [2] 1a 3d [2] 1c 08 [2] 32 08 [2] 0d 14 }

  condition:
    any of them
}