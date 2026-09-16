rule TTP_XOR_WriteProcessMemory_0d29 {
  strings:
    $key_0d29 = { 5a 5b [2] 68 79 [2] 6e 4c [2] 40 4c [2] 7f 50 }

  condition:
    any of them
}