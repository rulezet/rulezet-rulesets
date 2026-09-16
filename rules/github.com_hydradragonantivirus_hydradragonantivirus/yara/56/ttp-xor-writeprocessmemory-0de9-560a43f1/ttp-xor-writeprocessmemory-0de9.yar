rule TTP_XOR_WriteProcessMemory_0de9 {
  strings:
    $key_0de9 = { 5a 9b [2] 68 b9 [2] 6e 8c [2] 40 8c [2] 7f 90 }

  condition:
    any of them
}