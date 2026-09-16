rule TTP_XOR_WriteProcessMemory_6514 {
  strings:
    $key_6514 = { 32 66 [2] 00 44 [2] 06 71 [2] 28 71 [2] 17 6d }

  condition:
    any of them
}