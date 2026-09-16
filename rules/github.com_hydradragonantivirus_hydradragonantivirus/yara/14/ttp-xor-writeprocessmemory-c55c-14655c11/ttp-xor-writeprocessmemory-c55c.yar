rule TTP_XOR_WriteProcessMemory_c55c {
  strings:
    $key_c55c = { 92 2e [2] a0 0c [2] a6 39 [2] 88 39 [2] b7 25 }

  condition:
    any of them
}