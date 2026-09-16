rule TTP_XOR_WriteProcessMemory_7f47 {
  strings:
    $key_7f47 = { 28 35 [2] 1a 17 [2] 1c 22 [2] 32 22 [2] 0d 3e }

  condition:
    any of them
}