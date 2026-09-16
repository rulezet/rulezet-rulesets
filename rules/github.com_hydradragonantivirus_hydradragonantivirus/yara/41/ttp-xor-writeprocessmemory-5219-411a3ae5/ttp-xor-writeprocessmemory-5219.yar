rule TTP_XOR_WriteProcessMemory_5219 {
  strings:
    $key_5219 = { 05 6b [2] 37 49 [2] 31 7c [2] 1f 7c [2] 20 60 }

  condition:
    any of them
}