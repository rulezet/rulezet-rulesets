rule TTP_XOR_WriteProcessMemory_0909 {
  strings:
    $key_0909 = { 5e 7b [2] 6c 59 [2] 6a 6c [2] 44 6c [2] 7b 70 }

  condition:
    any of them
}