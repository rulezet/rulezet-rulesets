rule TTP_XOR_WriteProcessMemory_3962 {
  strings:
    $key_3962 = { 6e 10 [2] 5c 32 [2] 5a 07 [2] 74 07 [2] 4b 1b }

  condition:
    any of them
}