rule TTP_XOR_WriteProcessMemory_8d5d {
  strings:
    $key_8d5d = { da 2f [2] e8 0d [2] ee 38 [2] c0 38 [2] ff 24 }

  condition:
    any of them
}