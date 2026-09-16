rule TTP_XOR_WriteProcessMemory_6511 {
  strings:
    $key_6511 = { 32 63 [2] 00 41 [2] 06 74 [2] 28 74 [2] 17 68 }

  condition:
    any of them
}