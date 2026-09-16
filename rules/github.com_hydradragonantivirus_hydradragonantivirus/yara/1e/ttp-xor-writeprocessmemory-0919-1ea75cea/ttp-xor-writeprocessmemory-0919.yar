rule TTP_XOR_WriteProcessMemory_0919 {
  strings:
    $key_0919 = { 5e 6b [2] 6c 49 [2] 6a 7c [2] 44 7c [2] 7b 60 }

  condition:
    any of them
}