rule TTP_XOR_WriteProcessMemory_87e3 {
  strings:
    $key_87e3 = { d0 91 [2] e2 b3 [2] e4 86 [2] ca 86 [2] f5 9a }

  condition:
    any of them
}