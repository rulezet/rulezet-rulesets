rule TTP_XOR_WriteProcessMemory_00e1 {
  strings:
    $key_00e1 = { 57 93 [2] 65 b1 [2] 63 84 [2] 4d 84 [2] 72 98 }

  condition:
    any of them
}