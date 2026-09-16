rule TTP_XOR_WriteProcessMemory_c72e {
  strings:
    $key_c72e = { 90 5c [2] a2 7e [2] a4 4b [2] 8a 4b [2] b5 57 }

  condition:
    any of them
}