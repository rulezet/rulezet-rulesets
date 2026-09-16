rule TTP_XOR_WriteProcessMemory_b45a {
  strings:
    $key_b45a = { e3 28 [2] d1 0a [2] d7 3f [2] f9 3f [2] c6 23 }

  condition:
    any of them
}