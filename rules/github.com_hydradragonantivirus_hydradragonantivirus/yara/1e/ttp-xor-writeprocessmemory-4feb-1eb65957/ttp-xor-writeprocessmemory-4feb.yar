rule TTP_XOR_WriteProcessMemory_4feb {
  strings:
    $key_4feb = { 18 99 [2] 2a bb [2] 2c 8e [2] 02 8e [2] 3d 92 }

  condition:
    any of them
}