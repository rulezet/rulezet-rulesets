rule TTP_XOR_WriteProcessMemory_d309 {
  strings:
    $key_d309 = { 84 7b [2] b6 59 [2] b0 6c [2] 9e 6c [2] a1 70 }

  condition:
    any of them
}