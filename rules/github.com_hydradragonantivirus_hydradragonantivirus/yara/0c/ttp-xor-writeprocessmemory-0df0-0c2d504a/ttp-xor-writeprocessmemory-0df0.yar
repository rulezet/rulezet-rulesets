rule TTP_XOR_WriteProcessMemory_0df0 {
  strings:
    $key_0df0 = { 5a 82 [2] 68 a0 [2] 6e 95 [2] 40 95 [2] 7f 89 }

  condition:
    any of them
}