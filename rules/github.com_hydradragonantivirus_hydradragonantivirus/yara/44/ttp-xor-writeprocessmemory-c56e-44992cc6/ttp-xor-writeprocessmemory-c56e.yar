rule TTP_XOR_WriteProcessMemory_c56e {
  strings:
    $key_c56e = { 92 1c [2] a0 3e [2] a6 0b [2] 88 0b [2] b7 17 }

  condition:
    any of them
}