rule TTP_XOR_WriteProcessMemory_6520 {
  strings:
    $key_6520 = { 32 52 [2] 00 70 [2] 06 45 [2] 28 45 [2] 17 59 }

  condition:
    any of them
}