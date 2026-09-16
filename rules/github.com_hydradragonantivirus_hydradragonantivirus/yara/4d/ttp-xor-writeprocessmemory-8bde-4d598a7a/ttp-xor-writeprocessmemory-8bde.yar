rule TTP_XOR_WriteProcessMemory_8bde {
  strings:
    $key_8bde = { dc ac [2] ee 8e [2] e8 bb [2] c6 bb [2] f9 a7 }

  condition:
    any of them
}