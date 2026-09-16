rule TTP_XOR_WriteProcessMemory_851a {
  strings:
    $key_851a = { d2 68 [2] e0 4a [2] e6 7f [2] c8 7f [2] f7 63 }

  condition:
    any of them
}