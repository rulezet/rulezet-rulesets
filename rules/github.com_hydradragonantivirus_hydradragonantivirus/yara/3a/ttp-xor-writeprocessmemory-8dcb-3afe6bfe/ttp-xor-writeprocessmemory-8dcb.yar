rule TTP_XOR_WriteProcessMemory_8dcb {
  strings:
    $key_8dcb = { da b9 [2] e8 9b [2] ee ae [2] c0 ae [2] ff b2 }

  condition:
    any of them
}