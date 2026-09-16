rule TTP_XOR_WriteProcessMemory_1de1 {
  strings:
    $key_1de1 = { 4a 93 [2] 78 b1 [2] 7e 84 [2] 50 84 [2] 6f 98 }

  condition:
    any of them
}