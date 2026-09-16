rule TTP_XOR_WriteProcessMemory_caf9 {
  strings:
    $key_caf9 = { 9d 8b [2] af a9 [2] a9 9c [2] 87 9c [2] b8 80 }

  condition:
    any of them
}