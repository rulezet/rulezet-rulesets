rule TTP_XOR_WriteProcessMemory_8be3 {
  strings:
    $key_8be3 = { dc 91 [2] ee b3 [2] e8 86 [2] c6 86 [2] f9 9a }

  condition:
    any of them
}