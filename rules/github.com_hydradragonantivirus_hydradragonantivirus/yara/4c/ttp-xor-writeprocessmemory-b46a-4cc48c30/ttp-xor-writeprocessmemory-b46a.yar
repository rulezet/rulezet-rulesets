rule TTP_XOR_WriteProcessMemory_b46a {
  strings:
    $key_b46a = { e3 18 [2] d1 3a [2] d7 0f [2] f9 0f [2] c6 13 }

  condition:
    any of them
}