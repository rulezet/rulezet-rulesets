rule TTP_XOR_WriteProcessMemory_6f47 {
  strings:
    $key_6f47 = { 38 35 [2] 0a 17 [2] 0c 22 [2] 22 22 [2] 1d 3e }

  condition:
    any of them
}