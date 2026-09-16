rule TTP_XOR_WriteProcessMemory_0e67 {
  strings:
    $key_0e67 = { 59 15 [2] 6b 37 [2] 6d 02 [2] 43 02 [2] 7c 1e }

  condition:
    any of them
}