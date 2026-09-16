rule TTP_XOR_WriteProcessMemory_cbe1 {
  strings:
    $key_cbe1 = { 9c 93 [2] ae b1 [2] a8 84 [2] 86 84 [2] b9 98 }

  condition:
    any of them
}