rule TTP_XOR_WriteProcessMemory_2957 {
  strings:
    $key_2957 = { 7e 25 [2] 4c 07 [2] 4a 32 [2] 64 32 [2] 5b 2e }

  condition:
    any of them
}