rule TTP_XOR_WriteProcessMemory_d359 {
  strings:
    $key_d359 = { 84 2b [2] b6 09 [2] b0 3c [2] 9e 3c [2] a1 20 }

  condition:
    any of them
}