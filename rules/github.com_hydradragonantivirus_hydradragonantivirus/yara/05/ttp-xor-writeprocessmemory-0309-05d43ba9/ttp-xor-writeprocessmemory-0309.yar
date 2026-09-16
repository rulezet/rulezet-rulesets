rule TTP_XOR_WriteProcessMemory_0309 {
  strings:
    $key_0309 = { 54 7b [2] 66 59 [2] 60 6c [2] 4e 6c [2] 71 70 }

  condition:
    any of them
}