rule TTP_XOR_WriteProcessMemory_91ed {
  strings:
    $key_91ed = { c6 9f [2] f4 bd [2] f2 88 [2] dc 88 [2] e3 94 }

  condition:
    any of them
}