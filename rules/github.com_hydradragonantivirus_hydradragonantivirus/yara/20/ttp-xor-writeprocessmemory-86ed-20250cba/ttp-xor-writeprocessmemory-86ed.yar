rule TTP_XOR_WriteProcessMemory_86ed {
  strings:
    $key_86ed = { d1 9f [2] e3 bd [2] e5 88 [2] cb 88 [2] f4 94 }

  condition:
    any of them
}