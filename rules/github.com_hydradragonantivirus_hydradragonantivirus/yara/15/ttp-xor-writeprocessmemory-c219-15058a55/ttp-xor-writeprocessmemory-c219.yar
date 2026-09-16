rule TTP_XOR_WriteProcessMemory_c219 {
  strings:
    $key_c219 = { 95 6b [2] a7 49 [2] a1 7c [2] 8f 7c [2] b0 60 }

  condition:
    any of them
}