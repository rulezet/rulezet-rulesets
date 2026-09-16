rule TTP_XOR_WriteProcessMemory_0e30 {
  strings:
    $key_0e30 = { 59 42 [2] 6b 60 [2] 6d 55 [2] 43 55 [2] 7c 49 }

  condition:
    any of them
}