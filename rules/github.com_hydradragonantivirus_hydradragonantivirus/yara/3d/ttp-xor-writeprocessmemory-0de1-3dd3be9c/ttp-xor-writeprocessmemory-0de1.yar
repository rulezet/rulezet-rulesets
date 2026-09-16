rule TTP_XOR_WriteProcessMemory_0de1 {
  strings:
    $key_0de1 = { 5a 93 [2] 68 b1 [2] 6e 84 [2] 40 84 [2] 7f 98 }

  condition:
    any of them
}