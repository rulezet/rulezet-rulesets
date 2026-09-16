rule TTP_XOR_WriteProcessMemory_c269 {
  strings:
    $key_c269 = { 95 1b [2] a7 39 [2] a1 0c [2] 8f 0c [2] b0 10 }

  condition:
    any of them
}