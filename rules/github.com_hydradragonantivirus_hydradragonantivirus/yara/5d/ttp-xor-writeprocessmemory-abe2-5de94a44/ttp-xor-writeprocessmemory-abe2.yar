rule TTP_XOR_WriteProcessMemory_abe2 {
  strings:
    $key_abe2 = { fc 90 [2] ce b2 [2] c8 87 [2] e6 87 [2] d9 9b }

  condition:
    any of them
}