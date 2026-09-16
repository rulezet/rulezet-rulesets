rule TTP_XOR_WriteProcessMemory_04e1 {
  strings:
    $key_04e1 = { 53 93 [2] 61 b1 [2] 67 84 [2] 49 84 [2] 76 98 }

  condition:
    any of them
}