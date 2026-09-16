rule TTP_XOR_WriteProcessMemory_8323 {
  strings:
    $key_8323 = { d4 51 [2] e6 73 [2] e0 46 [2] ce 46 [2] f1 5a }

  condition:
    any of them
}