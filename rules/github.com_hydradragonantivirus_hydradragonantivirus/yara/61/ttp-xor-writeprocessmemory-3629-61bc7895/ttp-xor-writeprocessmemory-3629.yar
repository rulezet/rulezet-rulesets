rule TTP_XOR_WriteProcessMemory_3629 {
  strings:
    $key_3629 = { 61 5b [2] 53 79 [2] 55 4c [2] 7b 4c [2] 44 50 }

  condition:
    any of them
}