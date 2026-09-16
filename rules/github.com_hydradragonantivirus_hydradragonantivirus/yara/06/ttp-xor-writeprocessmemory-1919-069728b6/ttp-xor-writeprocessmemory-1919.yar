rule TTP_XOR_WriteProcessMemory_1919 {
  strings:
    $key_1919 = { 4e 6b [2] 7c 49 [2] 7a 7c [2] 54 7c [2] 6b 60 }

  condition:
    any of them
}