rule TTP_XOR_WriteProcessMemory_c52e {
  strings:
    $key_c52e = { 92 5c [2] a0 7e [2] a6 4b [2] 88 4b [2] b7 57 }

  condition:
    any of them
}