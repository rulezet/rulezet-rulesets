rule TTP_XOR_WriteProcessMemory_7f20 {
  strings:
    $key_7f20 = { 28 52 [2] 1a 70 [2] 1c 45 [2] 32 45 [2] 0d 59 }

  condition:
    any of them
}