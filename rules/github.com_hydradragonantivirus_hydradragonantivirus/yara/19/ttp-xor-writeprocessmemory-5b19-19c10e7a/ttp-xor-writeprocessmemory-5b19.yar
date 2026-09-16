rule TTP_XOR_WriteProcessMemory_5b19 {
  strings:
    $key_5b19 = { 0c 6b [2] 3e 49 [2] 38 7c [2] 16 7c [2] 29 60 }

  condition:
    any of them
}