rule TTP_XOR_WriteProcessMemory_8d1d {
  strings:
    $key_8d1d = { da 6f [2] e8 4d [2] ee 78 [2] c0 78 [2] ff 64 }

  condition:
    any of them
}