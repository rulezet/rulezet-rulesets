rule TTP_XOR_WriteProcessMemory_8d4a {
  strings:
    $key_8d4a = { da 38 [2] e8 1a [2] ee 2f [2] c0 2f [2] ff 33 }

  condition:
    any of them
}