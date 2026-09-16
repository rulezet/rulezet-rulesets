rule TTP_XOR_WriteProcessMemory_8623 {
  strings:
    $key_8623 = { d1 51 [2] e3 73 [2] e5 46 [2] cb 46 [2] f4 5a }

  condition:
    any of them
}