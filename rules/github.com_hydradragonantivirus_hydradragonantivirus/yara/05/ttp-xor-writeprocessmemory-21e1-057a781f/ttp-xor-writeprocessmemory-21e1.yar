rule TTP_XOR_WriteProcessMemory_21e1 {
  strings:
    $key_21e1 = { 76 93 [2] 44 b1 [2] 42 84 [2] 6c 84 [2] 53 98 }

  condition:
    any of them
}