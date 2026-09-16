rule TTP_XOR_WriteProcessMemory_b5ed {
  strings:
    $key_b5ed = { e2 9f [2] d0 bd [2] d6 88 [2] f8 88 [2] c7 94 }

  condition:
    any of them
}