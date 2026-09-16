rule TTP_XOR_WriteProcessMemory_8dfe {
  strings:
    $key_8dfe = { da 8c [2] e8 ae [2] ee 9b [2] c0 9b [2] ff 87 }

  condition:
    any of them
}