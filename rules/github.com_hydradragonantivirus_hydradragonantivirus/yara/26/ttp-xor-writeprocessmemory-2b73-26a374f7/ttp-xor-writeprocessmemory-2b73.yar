rule TTP_XOR_WriteProcessMemory_2b73 {
  strings:
    $key_2b73 = { 7c 01 [2] 4e 23 [2] 48 16 [2] 66 16 [2] 59 0a }

  condition:
    any of them
}