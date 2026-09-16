rule TTP_XOR_WriteProcessMemory_b43f {
  strings:
    $key_b43f = { e3 4d [2] d1 6f [2] d7 5a [2] f9 5a [2] c6 46 }

  condition:
    any of them
}