rule TTP_XOR_WriteProcessMemory_d029 {
  strings:
    $key_d029 = { 87 5b [2] b5 79 [2] b3 4c [2] 9d 4c [2] a2 50 }

  condition:
    any of them
}