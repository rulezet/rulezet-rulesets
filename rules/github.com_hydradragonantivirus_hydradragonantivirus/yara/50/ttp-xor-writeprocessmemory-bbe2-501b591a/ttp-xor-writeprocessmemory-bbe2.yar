rule TTP_XOR_WriteProcessMemory_bbe2 {
  strings:
    $key_bbe2 = { ec 90 [2] de b2 [2] d8 87 [2] f6 87 [2] c9 9b }

  condition:
    any of them
}