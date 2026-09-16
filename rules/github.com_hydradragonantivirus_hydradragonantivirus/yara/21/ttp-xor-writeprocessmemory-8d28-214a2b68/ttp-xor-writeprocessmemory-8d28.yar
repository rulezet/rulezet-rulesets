rule TTP_XOR_WriteProcessMemory_8d28 {
  strings:
    $key_8d28 = { da 5a [2] e8 78 [2] ee 4d [2] c0 4d [2] ff 51 }

  condition:
    any of them
}