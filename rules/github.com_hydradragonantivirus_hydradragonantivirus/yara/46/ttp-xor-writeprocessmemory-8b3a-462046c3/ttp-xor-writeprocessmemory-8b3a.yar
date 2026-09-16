rule TTP_XOR_WriteProcessMemory_8b3a {
  strings:
    $key_8b3a = { dc 48 [2] ee 6a [2] e8 5f [2] c6 5f [2] f9 43 }

  condition:
    any of them
}