rule TTP_XOR_WriteProcessMemory_8be9 {
  strings:
    $key_8be9 = { dc 9b [2] ee b9 [2] e8 8c [2] c6 8c [2] f9 90 }

  condition:
    any of them
}