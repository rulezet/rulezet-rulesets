rule TTP_XOR_WriteProcessMemory_8dfd {
  strings:
    $key_8dfd = { da 8f [2] e8 ad [2] ee 98 [2] c0 98 [2] ff 84 }

  condition:
    any of them
}