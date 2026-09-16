rule TTP_XOR_WriteProcessMemory_0f19 {
  strings:
    $key_0f19 = { 58 6b [2] 6a 49 [2] 6c 7c [2] 42 7c [2] 7d 60 }

  condition:
    any of them
}