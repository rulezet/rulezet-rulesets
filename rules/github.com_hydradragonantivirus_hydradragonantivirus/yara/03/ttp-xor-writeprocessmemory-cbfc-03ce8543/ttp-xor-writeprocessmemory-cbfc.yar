rule TTP_XOR_WriteProcessMemory_cbfc {
  strings:
    $key_cbfc = { 9c 8e [2] ae ac [2] a8 99 [2] 86 99 [2] b9 85 }

  condition:
    any of them
}