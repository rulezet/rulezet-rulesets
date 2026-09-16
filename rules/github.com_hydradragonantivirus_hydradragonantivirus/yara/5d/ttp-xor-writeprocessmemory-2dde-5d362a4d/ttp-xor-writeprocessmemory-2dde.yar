rule TTP_XOR_WriteProcessMemory_2dde {
  strings:
    $key_2dde = { 7a ac [2] 48 8e [2] 4e bb [2] 60 bb [2] 5f a7 }

  condition:
    any of them
}