rule TTP_XOR_WriteProcessMemory_2962 {
  strings:
    $key_2962 = { 7e 10 [2] 4c 32 [2] 4a 07 [2] 64 07 [2] 5b 1b }

  condition:
    any of them
}