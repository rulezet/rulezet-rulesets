rule TTP_XOR_WriteProcessMemory_c50c {
  strings:
    $key_c50c = { 92 7e [2] a0 5c [2] a6 69 [2] 88 69 [2] b7 75 }

  condition:
    any of them
}