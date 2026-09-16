rule TTP_XOR_WriteProcessMemory_bdc5 {
  strings:
    $key_bdc5 = { ea b7 [2] d8 95 [2] de a0 [2] f0 a0 [2] cf bc }

  condition:
    any of them
}