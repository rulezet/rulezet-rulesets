rule TTP_XOR_WriteProcessMemory_6b47 {
  strings:
    $key_6b47 = { 3c 35 [2] 0e 17 [2] 08 22 [2] 26 22 [2] 19 3e }

  condition:
    any of them
}