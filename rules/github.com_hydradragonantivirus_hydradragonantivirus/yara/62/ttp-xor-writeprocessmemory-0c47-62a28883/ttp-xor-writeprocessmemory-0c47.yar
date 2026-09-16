rule TTP_XOR_WriteProcessMemory_0c47 {
  strings:
    $key_0c47 = { 5b 35 [2] 69 17 [2] 6f 22 [2] 41 22 [2] 7e 3e }

  condition:
    any of them
}