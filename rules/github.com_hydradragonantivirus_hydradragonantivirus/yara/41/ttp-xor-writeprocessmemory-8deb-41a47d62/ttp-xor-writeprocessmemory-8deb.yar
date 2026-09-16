rule TTP_XOR_WriteProcessMemory_8deb {
  strings:
    $key_8deb = { da 99 [2] e8 bb [2] ee 8e [2] c0 8e [2] ff 92 }

  condition:
    any of them
}