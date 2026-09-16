rule TTP_XOR_WriteProcessMemory_ece9 {
  strings:
    $key_ece9 = { bb 9b [2] 89 b9 [2] 8f 8c [2] a1 8c [2] 9e 90 }

  condition:
    any of them
}