rule TTP_XOR_WriteProcessMemory_d319 {
  strings:
    $key_d319 = { 84 6b [2] b6 49 [2] b0 7c [2] 9e 7c [2] a1 60 }

  condition:
    any of them
}