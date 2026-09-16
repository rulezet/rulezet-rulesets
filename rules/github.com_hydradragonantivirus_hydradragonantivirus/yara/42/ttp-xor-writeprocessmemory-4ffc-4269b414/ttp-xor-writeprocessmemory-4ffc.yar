rule TTP_XOR_WriteProcessMemory_4ffc {
  strings:
    $key_4ffc = { 18 8e [2] 2a ac [2] 2c 99 [2] 02 99 [2] 3d 85 }

  condition:
    any of them
}