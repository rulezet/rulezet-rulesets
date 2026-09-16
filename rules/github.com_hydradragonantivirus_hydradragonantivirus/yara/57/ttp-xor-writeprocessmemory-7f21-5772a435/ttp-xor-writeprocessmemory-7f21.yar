rule TTP_XOR_WriteProcessMemory_7f21 {
  strings:
    $key_7f21 = { 28 53 [2] 1a 71 [2] 1c 44 [2] 32 44 [2] 0d 58 }

  condition:
    any of them
}