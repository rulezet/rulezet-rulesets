rule TTP_XOR_WriteProcessMemory_fdde {
  strings:
    $key_fdde = { aa ac [2] 98 8e [2] 9e bb [2] b0 bb [2] 8f a7 }

  condition:
    any of them
}