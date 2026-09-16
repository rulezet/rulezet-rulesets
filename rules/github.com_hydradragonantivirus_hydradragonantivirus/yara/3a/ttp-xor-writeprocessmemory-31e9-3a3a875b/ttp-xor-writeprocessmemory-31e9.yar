rule TTP_XOR_WriteProcessMemory_31e9 {
  strings:
    $key_31e9 = { 66 9b [2] 54 b9 [2] 52 8c [2] 7c 8c [2] 43 90 }

  condition:
    any of them
}