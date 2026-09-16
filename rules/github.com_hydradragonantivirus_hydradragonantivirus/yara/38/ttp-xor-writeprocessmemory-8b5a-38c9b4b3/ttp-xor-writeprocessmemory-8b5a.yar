rule TTP_XOR_WriteProcessMemory_8b5a {
  strings:
    $key_8b5a = { dc 28 [2] ee 0a [2] e8 3f [2] c6 3f [2] f9 23 }

  condition:
    any of them
}