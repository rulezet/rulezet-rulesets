rule TTP_XOR_WriteProcessMemory_c52c {
  strings:
    $key_c52c = { 92 5e [2] a0 7c [2] a6 49 [2] 88 49 [2] b7 55 }

  condition:
    any of them
}