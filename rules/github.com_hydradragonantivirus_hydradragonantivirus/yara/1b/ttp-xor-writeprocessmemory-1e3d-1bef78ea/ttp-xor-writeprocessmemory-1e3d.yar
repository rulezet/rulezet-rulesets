rule TTP_XOR_WriteProcessMemory_1e3d {
  strings:
    $key_1e3d = { 49 4f [2] 7b 6d [2] 7d 58 [2] 53 58 [2] 6c 44 }

  condition:
    any of them
}