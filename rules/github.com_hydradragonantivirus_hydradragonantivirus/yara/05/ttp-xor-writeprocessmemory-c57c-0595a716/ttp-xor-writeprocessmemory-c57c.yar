rule TTP_XOR_WriteProcessMemory_c57c {
  strings:
    $key_c57c = { 92 0e [2] a0 2c [2] a6 19 [2] 88 19 [2] b7 05 }

  condition:
    any of them
}