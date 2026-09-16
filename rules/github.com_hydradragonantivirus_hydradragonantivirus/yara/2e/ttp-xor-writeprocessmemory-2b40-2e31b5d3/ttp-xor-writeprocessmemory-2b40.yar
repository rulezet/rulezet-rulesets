rule TTP_XOR_WriteProcessMemory_2b40 {
  strings:
    $key_2b40 = { 7c 32 [2] 4e 10 [2] 48 25 [2] 66 25 [2] 59 39 }

  condition:
    any of them
}