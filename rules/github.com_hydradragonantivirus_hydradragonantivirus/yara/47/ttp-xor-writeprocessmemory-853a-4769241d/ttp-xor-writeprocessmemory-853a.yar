rule TTP_XOR_WriteProcessMemory_853a {
  strings:
    $key_853a = { d2 48 [2] e0 6a [2] e6 5f [2] c8 5f [2] f7 43 }

  condition:
    any of them
}