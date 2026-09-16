rule TTP_XOR_WriteProcessMemory_c21e {
  strings:
    $key_c21e = { 95 6c [2] a7 4e [2] a1 7b [2] 8f 7b [2] b0 67 }

  condition:
    any of them
}