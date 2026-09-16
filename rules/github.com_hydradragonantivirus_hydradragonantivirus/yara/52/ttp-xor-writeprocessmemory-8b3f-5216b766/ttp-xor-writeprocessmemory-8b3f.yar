rule TTP_XOR_WriteProcessMemory_8b3f {
  strings:
    $key_8b3f = { dc 4d [2] ee 6f [2] e8 5a [2] c6 5a [2] f9 46 }

  condition:
    any of them
}