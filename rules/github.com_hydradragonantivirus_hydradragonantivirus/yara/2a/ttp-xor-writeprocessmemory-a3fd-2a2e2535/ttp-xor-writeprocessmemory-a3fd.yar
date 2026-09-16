rule TTP_XOR_WriteProcessMemory_a3fd {
  strings:
    $key_a3fd = { f4 8f [2] c6 ad [2] c0 98 [2] ee 98 [2] d1 84 }

  condition:
    any of them
}