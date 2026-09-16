rule TTP_XOR_WriteProcessMemory_8d1c {
  strings:
    $key_8d1c = { da 6e [2] e8 4c [2] ee 79 [2] c0 79 [2] ff 65 }

  condition:
    any of them
}