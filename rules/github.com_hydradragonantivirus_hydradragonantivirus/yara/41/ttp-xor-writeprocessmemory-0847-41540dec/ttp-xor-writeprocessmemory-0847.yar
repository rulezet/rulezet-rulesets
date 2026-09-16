rule TTP_XOR_WriteProcessMemory_0847 {
  strings:
    $key_0847 = { 5f 35 [2] 6d 17 [2] 6b 22 [2] 45 22 [2] 7a 3e }

  condition:
    any of them
}