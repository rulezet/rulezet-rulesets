rule TTP_XOR_WriteProcessMemory_e929 {
  strings:
    $key_e929 = { be 5b [2] 8c 79 [2] 8a 4c [2] a4 4c [2] 9b 50 }

  condition:
    any of them
}