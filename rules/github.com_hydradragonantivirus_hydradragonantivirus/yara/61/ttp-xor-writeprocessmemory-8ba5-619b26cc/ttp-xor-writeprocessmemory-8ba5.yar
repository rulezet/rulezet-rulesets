rule TTP_XOR_WriteProcessMemory_8ba5 {
  strings:
    $key_8ba5 = { dc d7 [2] ee f5 [2] e8 c0 [2] c6 c0 [2] f9 dc }

  condition:
    any of them
}