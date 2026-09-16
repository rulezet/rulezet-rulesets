rule TTP_XOR_WriteProcessMemory_cafc {
  strings:
    $key_cafc = { 9d 8e [2] af ac [2] a9 99 [2] 87 99 [2] b8 85 }

  condition:
    any of them
}