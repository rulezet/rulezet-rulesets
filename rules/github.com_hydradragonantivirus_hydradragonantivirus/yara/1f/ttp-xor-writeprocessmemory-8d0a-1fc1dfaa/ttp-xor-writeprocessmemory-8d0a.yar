rule TTP_XOR_WriteProcessMemory_8d0a {
  strings:
    $key_8d0a = { da 78 [2] e8 5a [2] ee 6f [2] c0 6f [2] ff 73 }

  condition:
    any of them
}