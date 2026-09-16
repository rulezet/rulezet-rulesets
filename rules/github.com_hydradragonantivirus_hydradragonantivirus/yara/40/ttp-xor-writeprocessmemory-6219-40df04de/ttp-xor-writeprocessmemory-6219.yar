rule TTP_XOR_WriteProcessMemory_6219 {
  strings:
    $key_6219 = { 35 6b [2] 07 49 [2] 01 7c [2] 2f 7c [2] 10 60 }

  condition:
    any of them
}