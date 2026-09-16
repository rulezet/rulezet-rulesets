rule TTP_XOR_WriteProcessMemory_4914 {
  strings:
    $key_4914 = { 1e 66 [2] 2c 44 [2] 2a 71 [2] 04 71 [2] 3b 6d }

  condition:
    any of them
}