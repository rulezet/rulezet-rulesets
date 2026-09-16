rule TTP_XOR_WriteProcessMemory_8be8 {
  strings:
    $key_8be8 = { dc 9a [2] ee b8 [2] e8 8d [2] c6 8d [2] f9 91 }

  condition:
    any of them
}