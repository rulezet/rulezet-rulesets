rule TTP_XOR_WriteProcessMemory_5b47 {
  strings:
    $key_5b47 = { 0c 35 [2] 3e 17 [2] 38 22 [2] 16 22 [2] 29 3e }

  condition:
    any of them
}