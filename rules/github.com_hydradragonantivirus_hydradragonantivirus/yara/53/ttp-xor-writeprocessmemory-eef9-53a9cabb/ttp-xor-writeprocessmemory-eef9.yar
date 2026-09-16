rule TTP_XOR_WriteProcessMemory_eef9 {
  strings:
    $key_eef9 = { b9 8b [2] 8b a9 [2] 8d 9c [2] a3 9c [2] 9c 80 }

  condition:
    any of them
}