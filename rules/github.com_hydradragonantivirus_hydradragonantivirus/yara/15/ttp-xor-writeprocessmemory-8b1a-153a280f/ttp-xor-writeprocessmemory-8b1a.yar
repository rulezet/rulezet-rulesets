rule TTP_XOR_WriteProcessMemory_8b1a {
  strings:
    $key_8b1a = { dc 68 [2] ee 4a [2] e8 7f [2] c6 7f [2] f9 63 }

  condition:
    any of them
}