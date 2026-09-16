rule TTP_XOR_WriteProcessMemory_1f47 {
  strings:
    $key_1f47 = { 48 35 [2] 7a 17 [2] 7c 22 [2] 52 22 [2] 6d 3e }

  condition:
    any of them
}