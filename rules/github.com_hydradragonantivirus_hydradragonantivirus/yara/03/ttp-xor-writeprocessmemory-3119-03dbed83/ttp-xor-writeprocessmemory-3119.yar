rule TTP_XOR_WriteProcessMemory_3119 {
  strings:
    $key_3119 = { 66 6b [2] 54 49 [2] 52 7c [2] 7c 7c [2] 43 60 }

  condition:
    any of them
}