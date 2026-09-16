rule TTP_XOR_WriteProcessMemory_8bb2 {
  strings:
    $key_8bb2 = { dc c0 [2] ee e2 [2] e8 d7 [2] c6 d7 [2] f9 cb }

  condition:
    any of them
}