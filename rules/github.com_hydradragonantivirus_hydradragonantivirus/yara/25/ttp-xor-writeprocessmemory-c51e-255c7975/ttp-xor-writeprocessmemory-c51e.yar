rule TTP_XOR_WriteProcessMemory_c51e {
  strings:
    $key_c51e = { 92 6c [2] a0 4e [2] a6 7b [2] 88 7b [2] b7 67 }

  condition:
    any of them
}