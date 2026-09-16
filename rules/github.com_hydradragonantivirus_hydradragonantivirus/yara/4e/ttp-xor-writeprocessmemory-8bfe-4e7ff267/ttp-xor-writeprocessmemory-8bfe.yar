rule TTP_XOR_WriteProcessMemory_8bfe {
  strings:
    $key_8bfe = { dc 8c [2] ee ae [2] e8 9b [2] c6 9b [2] f9 87 }

  condition:
    any of them
}