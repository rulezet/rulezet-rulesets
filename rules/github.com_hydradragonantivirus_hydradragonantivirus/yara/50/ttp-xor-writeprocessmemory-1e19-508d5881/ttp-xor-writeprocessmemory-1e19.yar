rule TTP_XOR_WriteProcessMemory_1e19 {
  strings:
    $key_1e19 = { 49 6b [2] 7b 49 [2] 7d 7c [2] 53 7c [2] 6c 60 }

  condition:
    any of them
}