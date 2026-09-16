rule TTP_XOR_WriteProcessMemory_d40e {
  strings:
    $key_d40e = { 83 7c [2] b1 5e [2] b7 6b [2] 99 6b [2] a6 77 }

  condition:
    any of them
}