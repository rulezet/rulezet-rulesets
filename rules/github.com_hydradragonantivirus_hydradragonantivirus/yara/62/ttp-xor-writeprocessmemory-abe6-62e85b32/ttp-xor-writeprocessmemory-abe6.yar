rule TTP_XOR_WriteProcessMemory_abe6 {
  strings:
    $key_abe6 = { fc 94 [2] ce b6 [2] c8 83 [2] e6 83 [2] d9 9f }

  condition:
    any of them
}