rule TTP_XOR_WriteProcessMemory_8d7f {
  strings:
    $key_8d7f = { da 0d [2] e8 2f [2] ee 1a [2] c0 1a [2] ff 06 }

  condition:
    any of them
}