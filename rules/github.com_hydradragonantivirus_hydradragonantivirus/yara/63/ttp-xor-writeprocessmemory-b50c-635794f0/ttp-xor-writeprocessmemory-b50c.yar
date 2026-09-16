rule TTP_XOR_WriteProcessMemory_b50c {
  strings:
    $key_b50c = { e2 7e [2] d0 5c [2] d6 69 [2] f8 69 [2] c7 75 }

  condition:
    any of them
}