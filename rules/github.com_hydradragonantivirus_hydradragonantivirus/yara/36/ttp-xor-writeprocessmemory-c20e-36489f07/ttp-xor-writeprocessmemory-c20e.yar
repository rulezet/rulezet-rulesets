rule TTP_XOR_WriteProcessMemory_c20e {
  strings:
    $key_c20e = { 95 7c [2] a7 5e [2] a1 6b [2] 8f 6b [2] b0 77 }

  condition:
    any of them
}