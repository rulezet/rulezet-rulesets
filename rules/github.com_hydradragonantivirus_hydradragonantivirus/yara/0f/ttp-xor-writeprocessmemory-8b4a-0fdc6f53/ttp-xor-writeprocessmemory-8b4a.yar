rule TTP_XOR_WriteProcessMemory_8b4a {
  strings:
    $key_8b4a = { dc 38 [2] ee 1a [2] e8 2f [2] c6 2f [2] f9 33 }

  condition:
    any of them
}