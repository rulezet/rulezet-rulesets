rule TTP_XOR_WriteProcessMemory_0df9 {
  strings:
    $key_0df9 = { 5a 8b [2] 68 a9 [2] 6e 9c [2] 40 9c [2] 7f 80 }

  condition:
    any of them
}