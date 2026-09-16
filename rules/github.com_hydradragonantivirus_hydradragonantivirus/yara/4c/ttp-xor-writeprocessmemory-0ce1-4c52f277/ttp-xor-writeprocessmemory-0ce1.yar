rule TTP_XOR_WriteProcessMemory_0ce1 {
  strings:
    $key_0ce1 = { 5b 93 [2] 69 b1 [2] 6f 84 [2] 41 84 [2] 7e 98 }

  condition:
    any of them
}