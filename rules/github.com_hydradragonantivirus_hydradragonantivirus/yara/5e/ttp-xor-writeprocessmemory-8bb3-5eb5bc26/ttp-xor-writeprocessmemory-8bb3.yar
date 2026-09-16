rule TTP_XOR_WriteProcessMemory_8bb3 {
  strings:
    $key_8bb3 = { dc c1 [2] ee e3 [2] e8 d6 [2] c6 d6 [2] f9 ca }

  condition:
    any of them
}