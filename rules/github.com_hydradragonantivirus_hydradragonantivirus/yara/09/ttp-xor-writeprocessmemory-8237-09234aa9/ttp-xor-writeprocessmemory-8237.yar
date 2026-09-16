rule TTP_XOR_WriteProcessMemory_8237 {
  strings:
    $key_8237 = { d5 45 [2] e7 67 [2] e1 52 [2] cf 52 [2] f0 4e }

  condition:
    any of them
}