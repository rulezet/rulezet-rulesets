rule TTP_XOR_WriteProcessMemory_94ed {
  strings:
    $key_94ed = { c3 9f [2] f1 bd [2] f7 88 [2] d9 88 [2] e6 94 }

  condition:
    any of them
}