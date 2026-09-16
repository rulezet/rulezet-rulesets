rule TTP_XOR_WriteProcessMemory_3be1 {
  strings:
    $key_3be1 = { 6c 93 [2] 5e b1 [2] 58 84 [2] 76 84 [2] 49 98 }

  condition:
    any of them
}