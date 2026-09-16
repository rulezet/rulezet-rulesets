rule TTP_XOR_WriteProcessMemory_5f47 {
  strings:
    $key_5f47 = { 08 35 [2] 3a 17 [2] 3c 22 [2] 12 22 [2] 2d 3e }

  condition:
    any of them
}