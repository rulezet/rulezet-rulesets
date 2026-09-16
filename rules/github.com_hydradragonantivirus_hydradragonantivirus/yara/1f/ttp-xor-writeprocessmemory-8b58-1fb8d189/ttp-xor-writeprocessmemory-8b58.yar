rule TTP_XOR_WriteProcessMemory_8b58 {
  strings:
    $key_8b58 = { dc 2a [2] ee 08 [2] e8 3d [2] c6 3d [2] f9 21 }

  condition:
    any of them
}