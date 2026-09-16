rule TTP_XOR_WriteProcessMemory_6c19 {
  strings:
    $key_6c19 = { 3b 6b [2] 09 49 [2] 0f 7c [2] 21 7c [2] 1e 60 }

  condition:
    any of them
}