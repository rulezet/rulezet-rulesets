rule TTP_XOR_WriteProcessMemory_83b9 {
  strings:
    $key_83b9 = { d4 cb [2] e6 e9 [2] e0 dc [2] ce dc [2] f1 c0 }

  condition:
    any of them
}