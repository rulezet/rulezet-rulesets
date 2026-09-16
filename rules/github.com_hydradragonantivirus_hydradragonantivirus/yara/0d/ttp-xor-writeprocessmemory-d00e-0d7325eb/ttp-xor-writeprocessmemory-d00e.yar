rule TTP_XOR_WriteProcessMemory_d00e {
  strings:
    $key_d00e = { 87 7c [2] b5 5e [2] b3 6b [2] 9d 6b [2] a2 77 }

  condition:
    any of them
}