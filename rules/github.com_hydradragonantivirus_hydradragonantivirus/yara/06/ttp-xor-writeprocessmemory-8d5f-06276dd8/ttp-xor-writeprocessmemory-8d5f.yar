rule TTP_XOR_WriteProcessMemory_8d5f {
  strings:
    $key_8d5f = { da 2d [2] e8 0f [2] ee 3a [2] c0 3a [2] ff 26 }

  condition:
    any of them
}