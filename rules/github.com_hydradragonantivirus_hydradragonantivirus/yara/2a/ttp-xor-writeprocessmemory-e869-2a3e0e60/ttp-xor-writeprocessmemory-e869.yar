rule TTP_XOR_WriteProcessMemory_e869 {
  strings:
    $key_e869 = { bf 1b [2] 8d 39 [2] 8b 0c [2] a5 0c [2] 9a 10 }

  condition:
    any of them
}