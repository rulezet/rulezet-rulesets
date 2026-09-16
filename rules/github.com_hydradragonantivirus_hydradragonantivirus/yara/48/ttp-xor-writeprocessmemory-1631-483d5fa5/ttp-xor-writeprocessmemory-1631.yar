rule TTP_XOR_WriteProcessMemory_1631 {
  strings:
    $key_1631 = { 41 43 [2] 73 61 [2] 75 54 [2] 5b 54 [2] 64 48 }

  condition:
    any of them
}