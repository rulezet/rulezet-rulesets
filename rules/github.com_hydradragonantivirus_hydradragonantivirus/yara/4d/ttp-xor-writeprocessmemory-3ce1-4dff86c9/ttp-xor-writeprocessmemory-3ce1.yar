rule TTP_XOR_WriteProcessMemory_3ce1 {
  strings:
    $key_3ce1 = { 6b 93 [2] 59 b1 [2] 5f 84 [2] 71 84 [2] 4e 98 }

  condition:
    any of them
}