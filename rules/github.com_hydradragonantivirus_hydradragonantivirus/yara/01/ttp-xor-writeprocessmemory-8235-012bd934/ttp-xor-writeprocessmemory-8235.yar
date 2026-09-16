rule TTP_XOR_WriteProcessMemory_8235 {
  strings:
    $key_8235 = { d5 47 [2] e7 65 [2] e1 50 [2] cf 50 [2] f0 4c }

  condition:
    any of them
}