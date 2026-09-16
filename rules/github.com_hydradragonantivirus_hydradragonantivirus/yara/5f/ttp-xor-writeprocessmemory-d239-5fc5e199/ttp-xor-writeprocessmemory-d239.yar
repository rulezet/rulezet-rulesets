rule TTP_XOR_WriteProcessMemory_d239 {
  strings:
    $key_d239 = { 85 4b [2] b7 69 [2] b1 5c [2] 9f 5c [2] a0 40 }

  condition:
    any of them
}