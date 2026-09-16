rule TTP_XOR_WriteProcessMemory_8d3c {
  strings:
    $key_8d3c = { da 4e [2] e8 6c [2] ee 59 [2] c0 59 [2] ff 45 }

  condition:
    any of them
}