rule TTP_XOR_WriteProcessMemory_7f14 {
  strings:
    $key_7f14 = { 28 66 [2] 1a 44 [2] 1c 71 [2] 32 71 [2] 0d 6d }

  condition:
    any of them
}