rule TTP_XOR_WriteProcessMemory_e829 {
  strings:
    $key_e829 = { bf 5b [2] 8d 79 [2] 8b 4c [2] a5 4c [2] 9a 50 }

  condition:
    any of them
}