rule TTP_XOR_WriteProcessMemory_0f47 {
  strings:
    $key_0f47 = { 58 35 [2] 6a 17 [2] 6c 22 [2] 42 22 [2] 7d 3e }

  condition:
    any of them
}