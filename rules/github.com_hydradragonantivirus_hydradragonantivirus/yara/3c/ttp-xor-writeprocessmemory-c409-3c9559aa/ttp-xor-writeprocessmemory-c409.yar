rule TTP_XOR_WriteProcessMemory_c409 {
  strings:
    $key_c409 = { 93 7b [2] a1 59 [2] a7 6c [2] 89 6c [2] b6 70 }

  condition:
    any of them
}