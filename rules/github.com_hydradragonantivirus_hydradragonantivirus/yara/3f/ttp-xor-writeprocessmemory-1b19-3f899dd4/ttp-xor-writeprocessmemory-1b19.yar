rule TTP_XOR_WriteProcessMemory_1b19 {
  strings:
    $key_1b19 = { 4c 6b [2] 7e 49 [2] 78 7c [2] 56 7c [2] 69 60 }

  condition:
    any of them
}