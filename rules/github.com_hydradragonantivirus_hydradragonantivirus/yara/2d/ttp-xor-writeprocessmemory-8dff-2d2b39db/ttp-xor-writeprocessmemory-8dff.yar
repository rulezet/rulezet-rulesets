rule TTP_XOR_WriteProcessMemory_8dff {
  strings:
    $key_8dff = { da 8d [2] e8 af [2] ee 9a [2] c0 9a [2] ff 86 }

  condition:
    any of them
}