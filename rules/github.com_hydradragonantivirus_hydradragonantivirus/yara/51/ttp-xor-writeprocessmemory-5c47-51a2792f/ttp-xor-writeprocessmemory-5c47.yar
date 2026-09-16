rule TTP_XOR_WriteProcessMemory_5c47 {
  strings:
    $key_5c47 = { 0b 35 [2] 39 17 [2] 3f 22 [2] 11 22 [2] 2e 3e }

  condition:
    any of them
}