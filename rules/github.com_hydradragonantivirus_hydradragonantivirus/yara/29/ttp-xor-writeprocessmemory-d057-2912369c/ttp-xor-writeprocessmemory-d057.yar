rule TTP_XOR_WriteProcessMemory_d057 {
  strings:
    $key_d057 = { 87 25 [2] b5 07 [2] b3 32 [2] 9d 32 [2] a2 2e }

  condition:
    any of them
}