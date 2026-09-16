rule TTP_XOR_WriteProcessMemory_0907 {
  strings:
    $key_0907 = { 5e 75 [2] 6c 57 [2] 6a 62 [2] 44 62 [2] 7b 7e }

  condition:
    any of them
}