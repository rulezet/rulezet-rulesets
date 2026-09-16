rule TTP_XOR_WriteProcessMemory_38e1 {
  strings:
    $key_38e1 = { 6f 93 [2] 5d b1 [2] 5b 84 [2] 75 84 [2] 4a 98 }

  condition:
    any of them
}