rule TTP_XOR_WriteProcessMemory_c239 {
  strings:
    $key_c239 = { 95 4b [2] a7 69 [2] a1 5c [2] 8f 5c [2] b0 40 }

  condition:
    any of them
}