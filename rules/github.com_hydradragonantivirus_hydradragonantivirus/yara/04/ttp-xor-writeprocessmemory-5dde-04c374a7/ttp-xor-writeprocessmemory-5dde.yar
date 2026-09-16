rule TTP_XOR_WriteProcessMemory_5dde {
  strings:
    $key_5dde = { 0a ac [2] 38 8e [2] 3e bb [2] 10 bb [2] 2f a7 }

  condition:
    any of them
}