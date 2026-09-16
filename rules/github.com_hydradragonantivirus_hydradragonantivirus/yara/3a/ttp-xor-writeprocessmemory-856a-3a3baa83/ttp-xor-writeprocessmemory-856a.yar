rule TTP_XOR_WriteProcessMemory_856a {
  strings:
    $key_856a = { d2 18 [2] e0 3a [2] e6 0f [2] c8 0f [2] f7 13 }

  condition:
    any of them
}