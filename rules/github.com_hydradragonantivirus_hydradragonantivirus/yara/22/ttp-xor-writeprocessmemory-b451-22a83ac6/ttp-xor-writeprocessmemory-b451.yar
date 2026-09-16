rule TTP_XOR_WriteProcessMemory_b451 {
  strings:
    $key_b451 = { e3 23 [2] d1 01 [2] d7 34 [2] f9 34 [2] c6 28 }

  condition:
    any of them
}