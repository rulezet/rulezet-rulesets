rule TTP_XOR_WriteProcessMemory_4b47 {
  strings:
    $key_4b47 = { 1c 35 [2] 2e 17 [2] 28 22 [2] 06 22 [2] 39 3e }

  condition:
    any of them
}