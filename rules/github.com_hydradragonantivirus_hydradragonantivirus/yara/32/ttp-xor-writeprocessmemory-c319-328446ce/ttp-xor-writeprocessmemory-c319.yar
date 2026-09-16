rule TTP_XOR_WriteProcessMemory_c319 {
  strings:
    $key_c319 = { 94 6b [2] a6 49 [2] a0 7c [2] 8e 7c [2] b1 60 }

  condition:
    any of them
}