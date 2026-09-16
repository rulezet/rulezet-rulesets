rule TTP_XOR_WriteProcessMemory_8b2f {
  strings:
    $key_8b2f = { dc 5d [2] ee 7f [2] e8 4a [2] c6 4a [2] f9 56 }

  condition:
    any of them
}