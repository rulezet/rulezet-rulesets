rule TTP_XOR_WriteProcessMemory_0967 {
  strings:
    $key_0967 = { 5e 15 [2] 6c 37 [2] 6a 02 [2] 44 02 [2] 7b 1e }

  condition:
    any of them
}