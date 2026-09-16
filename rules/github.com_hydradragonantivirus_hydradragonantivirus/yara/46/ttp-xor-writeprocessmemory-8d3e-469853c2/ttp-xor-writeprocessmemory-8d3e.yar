rule TTP_XOR_WriteProcessMemory_8d3e {
  strings:
    $key_8d3e = { da 4c [2] e8 6e [2] ee 5b [2] c0 5b [2] ff 47 }

  condition:
    any of them
}