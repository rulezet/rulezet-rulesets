rule TTP_XOR_WriteProcessMemory_b51a {
  strings:
    $key_b51a = { e2 68 [2] d0 4a [2] d6 7f [2] f8 7f [2] c7 63 }

  condition:
    any of them
}