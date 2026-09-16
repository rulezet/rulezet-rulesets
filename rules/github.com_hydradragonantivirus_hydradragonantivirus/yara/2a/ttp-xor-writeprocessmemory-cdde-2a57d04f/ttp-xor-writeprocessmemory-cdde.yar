rule TTP_XOR_WriteProcessMemory_cdde {
  strings:
    $key_cdde = { 9a ac [2] a8 8e [2] ae bb [2] 80 bb [2] bf a7 }

  condition:
    any of them
}