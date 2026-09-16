rule TTP_XOR_WriteProcessMemory_8b0a {
  strings:
    $key_8b0a = { dc 78 [2] ee 5a [2] e8 6f [2] c6 6f [2] f9 73 }

  condition:
    any of them
}