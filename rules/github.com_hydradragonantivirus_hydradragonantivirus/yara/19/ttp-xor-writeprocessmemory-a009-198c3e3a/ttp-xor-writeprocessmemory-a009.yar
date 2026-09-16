rule TTP_XOR_WriteProcessMemory_a009 {
  strings:
    $key_a009 = { f7 7b [2] c5 59 [2] c3 6c [2] ed 6c [2] d2 70 }

  condition:
    any of them
}