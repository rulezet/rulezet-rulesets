rule TTP_XOR_WriteProcessMemory_2b22 {
  strings:
    $key_2b22 = { 7c 50 [2] 4e 72 [2] 48 47 [2] 66 47 [2] 59 5b }

  condition:
    any of them
}