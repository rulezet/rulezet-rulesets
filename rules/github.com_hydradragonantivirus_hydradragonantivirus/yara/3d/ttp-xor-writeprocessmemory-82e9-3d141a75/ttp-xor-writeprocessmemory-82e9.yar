rule TTP_XOR_WriteProcessMemory_82e9 {
  strings:
    $key_82e9 = { d5 9b [2] e7 b9 [2] e1 8c [2] cf 8c [2] f0 90 }

  condition:
    any of them
}