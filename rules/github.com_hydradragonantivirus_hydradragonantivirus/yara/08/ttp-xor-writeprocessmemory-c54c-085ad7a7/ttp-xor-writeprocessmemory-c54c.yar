rule TTP_XOR_WriteProcessMemory_c54c {
  strings:
    $key_c54c = { 92 3e [2] a0 1c [2] a6 29 [2] 88 29 [2] b7 35 }

  condition:
    any of them
}