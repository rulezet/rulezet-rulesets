rule TTP_XOR_WriteProcessMemory_5104 {
  strings:
    $key_5104 = { 06 76 [2] 34 54 [2] 32 61 [2] 1c 61 [2] 23 7d }

  condition:
    any of them
}