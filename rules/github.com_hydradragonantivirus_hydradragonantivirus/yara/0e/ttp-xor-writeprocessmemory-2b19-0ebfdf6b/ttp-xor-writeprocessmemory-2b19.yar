rule TTP_XOR_WriteProcessMemory_2b19 {
  strings:
    $key_2b19 = { 7c 6b [2] 4e 49 [2] 48 7c [2] 66 7c [2] 59 60 }

  condition:
    any of them
}