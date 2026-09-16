rule TTP_XOR_WriteProcessMemory_b50d {
  strings:
    $key_b50d = { e2 7f [2] d0 5d [2] d6 68 [2] f8 68 [2] c7 74 }

  condition:
    any of them
}