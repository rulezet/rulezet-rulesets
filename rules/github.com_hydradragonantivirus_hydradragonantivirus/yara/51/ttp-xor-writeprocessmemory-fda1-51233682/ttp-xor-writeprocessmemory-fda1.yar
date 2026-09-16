rule TTP_XOR_WriteProcessMemory_fda1 {
  strings:
    $key_fda1 = { aa d3 [2] 98 f1 [2] 9e c4 [2] b0 c4 [2] 8f d8 }

  condition:
    any of them
}