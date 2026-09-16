rule TTP_XOR_WriteProcessMemory_7de1 {
  strings:
    $key_7de1 = { 2a 93 [2] 18 b1 [2] 1e 84 [2] 30 84 [2] 0f 98 }

  condition:
    any of them
}