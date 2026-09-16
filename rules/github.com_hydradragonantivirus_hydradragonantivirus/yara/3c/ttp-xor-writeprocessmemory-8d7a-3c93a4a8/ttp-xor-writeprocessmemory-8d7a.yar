rule TTP_XOR_WriteProcessMemory_8d7a {
  strings:
    $key_8d7a = { da 08 [2] e8 2a [2] ee 1f [2] c0 1f [2] ff 03 }

  condition:
    any of them
}