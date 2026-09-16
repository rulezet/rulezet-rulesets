rule TTP_XOR_WriteProcessMemory_5131 {
  strings:
    $key_5131 = { 06 43 [2] 34 61 [2] 32 54 [2] 1c 54 [2] 23 48 }

  condition:
    any of them
}