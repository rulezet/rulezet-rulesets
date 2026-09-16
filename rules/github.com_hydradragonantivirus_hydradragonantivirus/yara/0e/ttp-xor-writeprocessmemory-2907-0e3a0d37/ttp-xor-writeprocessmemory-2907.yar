rule TTP_XOR_WriteProcessMemory_2907 {
  strings:
    $key_2907 = { 7e 75 [2] 4c 57 [2] 4a 62 [2] 64 62 [2] 5b 7e }

  condition:
    any of them
}