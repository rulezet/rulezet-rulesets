rule TTP_XOR_WriteProcessMemory_c339 {
  strings:
    $key_c339 = { 94 4b [2] a6 69 [2] a0 5c [2] 8e 5c [2] b1 40 }

  condition:
    any of them
}