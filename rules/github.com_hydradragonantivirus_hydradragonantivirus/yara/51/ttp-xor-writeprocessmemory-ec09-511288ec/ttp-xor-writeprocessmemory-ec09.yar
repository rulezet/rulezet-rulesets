rule TTP_XOR_WriteProcessMemory_ec09 {
  strings:
    $key_ec09 = { bb 7b [2] 89 59 [2] 8f 6c [2] a1 6c [2] 9e 70 }

  condition:
    any of them
}