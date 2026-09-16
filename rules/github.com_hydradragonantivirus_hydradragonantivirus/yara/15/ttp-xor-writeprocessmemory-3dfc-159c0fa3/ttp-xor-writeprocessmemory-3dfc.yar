rule TTP_XOR_WriteProcessMemory_3dfc {
  strings:
    $key_3dfc = { 6a 8e [2] 58 ac [2] 5e 99 [2] 70 99 [2] 4f 85 }

  condition:
    any of them
}