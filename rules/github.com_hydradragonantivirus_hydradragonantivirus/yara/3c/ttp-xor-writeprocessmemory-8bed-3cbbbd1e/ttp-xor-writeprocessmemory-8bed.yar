rule TTP_XOR_WriteProcessMemory_8bed {
  strings:
    $key_8bed = { dc 9f [2] ee bd [2] e8 88 [2] c6 88 [2] f9 94 }

  condition:
    any of them
}