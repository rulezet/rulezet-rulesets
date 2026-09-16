rule TTP_XOR_WriteProcessMemory_d469 {
  strings:
    $key_d469 = { 83 1b [2] b1 39 [2] b7 0c [2] 99 0c [2] a6 10 }

  condition:
    any of them
}