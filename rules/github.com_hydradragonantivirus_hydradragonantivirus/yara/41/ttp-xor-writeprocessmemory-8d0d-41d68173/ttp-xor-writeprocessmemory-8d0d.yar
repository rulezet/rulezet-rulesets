rule TTP_XOR_WriteProcessMemory_8d0d {
  strings:
    $key_8d0d = { da 7f [2] e8 5d [2] ee 68 [2] c0 68 [2] ff 74 }

  condition:
    any of them
}