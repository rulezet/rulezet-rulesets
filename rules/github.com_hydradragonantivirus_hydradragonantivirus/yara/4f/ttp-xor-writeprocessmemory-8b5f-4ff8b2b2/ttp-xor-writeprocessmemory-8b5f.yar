rule TTP_XOR_WriteProcessMemory_8b5f {
  strings:
    $key_8b5f = { dc 2d [2] ee 0f [2] e8 3a [2] c6 3a [2] f9 26 }

  condition:
    any of them
}