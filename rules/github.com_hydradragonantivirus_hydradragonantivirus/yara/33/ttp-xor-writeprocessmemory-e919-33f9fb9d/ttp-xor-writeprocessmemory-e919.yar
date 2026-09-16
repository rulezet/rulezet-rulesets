rule TTP_XOR_WriteProcessMemory_e919 {
  strings:
    $key_e919 = { be 6b [2] 8c 49 [2] 8a 7c [2] a4 7c [2] 9b 60 }

  condition:
    any of them
}