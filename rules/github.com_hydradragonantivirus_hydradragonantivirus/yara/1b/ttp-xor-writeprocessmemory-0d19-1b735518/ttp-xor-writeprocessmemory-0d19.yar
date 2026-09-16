rule TTP_XOR_WriteProcessMemory_0d19 {
  strings:
    $key_0d19 = { 5a 6b [2] 68 49 [2] 6e 7c [2] 40 7c [2] 7f 60 }

  condition:
    any of them
}