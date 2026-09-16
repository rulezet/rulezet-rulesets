rule TTP_XOR_WriteProcessMemory_8311 {
  strings:
    $key_8311 = { d4 63 [2] e6 41 [2] e0 74 [2] ce 74 [2] f1 68 }

  condition:
    any of them
}