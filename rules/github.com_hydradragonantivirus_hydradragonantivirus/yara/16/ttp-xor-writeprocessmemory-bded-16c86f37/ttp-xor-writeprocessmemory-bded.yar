rule TTP_XOR_WriteProcessMemory_bded {
  strings:
    $key_bded = { ea 9f [2] d8 bd [2] de 88 [2] f0 88 [2] cf 94 }

  condition:
    any of them
}