rule TTP_XOR_WriteProcessMemory_2b29 {
  strings:
    $key_2b29 = { 7c 5b [2] 4e 79 [2] 48 4c [2] 66 4c [2] 59 50 }

  condition:
    any of them
}