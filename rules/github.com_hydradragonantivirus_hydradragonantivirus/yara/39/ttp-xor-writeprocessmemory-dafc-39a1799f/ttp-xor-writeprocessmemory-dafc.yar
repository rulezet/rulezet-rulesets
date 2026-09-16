rule TTP_XOR_WriteProcessMemory_dafc {
  strings:
    $key_dafc = { 8d 8e [2] bf ac [2] b9 99 [2] 97 99 [2] a8 85 }

  condition:
    any of them
}