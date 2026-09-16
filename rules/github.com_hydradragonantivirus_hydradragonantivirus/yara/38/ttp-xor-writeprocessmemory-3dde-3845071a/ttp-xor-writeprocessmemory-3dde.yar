rule TTP_XOR_WriteProcessMemory_3dde {
  strings:
    $key_3dde = { 6a ac [2] 58 8e [2] 5e bb [2] 70 bb [2] 4f a7 }

  condition:
    any of them
}