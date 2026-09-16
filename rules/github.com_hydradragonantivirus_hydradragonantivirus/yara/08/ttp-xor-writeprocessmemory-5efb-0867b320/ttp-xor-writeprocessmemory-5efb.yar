rule TTP_XOR_WriteProcessMemory_5efb {
  strings:
    $key_5efb = { 09 89 [2] 3b ab [2] 3d 9e [2] 13 9e [2] 2c 82 }

  condition:
    any of them
}