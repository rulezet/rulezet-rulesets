rule TTP_XOR_WriteProcessMemory_acde {
  strings:
    $key_acde = { fb ac [2] c9 8e [2] cf bb [2] e1 bb [2] de a7 }

  condition:
    any of them
}