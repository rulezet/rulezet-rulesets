rule TTP_XOR_WriteProcessMemory_2147 {
  strings:
    $key_2147 = { 76 35 [2] 44 17 [2] 42 22 [2] 6c 22 [2] 53 3e }

  condition:
    any of them
}