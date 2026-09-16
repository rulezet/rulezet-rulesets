rule TTP_XOR_WriteProcessMemory_8d4c {
  strings:
    $key_8d4c = { da 3e [2] e8 1c [2] ee 29 [2] c0 29 [2] ff 35 }

  condition:
    any of them
}