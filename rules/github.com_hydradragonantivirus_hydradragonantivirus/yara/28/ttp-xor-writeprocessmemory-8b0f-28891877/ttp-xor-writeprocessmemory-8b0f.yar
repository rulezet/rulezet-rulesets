rule TTP_XOR_WriteProcessMemory_8b0f {
  strings:
    $key_8b0f = { dc 7d [2] ee 5f [2] e8 6a [2] c6 6a [2] f9 76 }

  condition:
    any of them
}