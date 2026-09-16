rule TTP_XOR_WriteProcessMemory_7ce1 {
  strings:
    $key_7ce1 = { 2b 93 [2] 19 b1 [2] 1f 84 [2] 31 84 [2] 0e 98 }

  condition:
    any of them
}