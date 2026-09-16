rule TTP_XOR_WriteProcessMemory_8bdf {
  strings:
    $key_8bdf = { dc ad [2] ee 8f [2] e8 ba [2] c6 ba [2] f9 a6 }

  condition:
    any of them
}