rule TTP_XOR_WriteProcessMemory_c5ed {
  strings:
    $key_c5ed = { 92 9f [2] a0 bd [2] a6 88 [2] 88 88 [2] b7 94 }

  condition:
    any of them
}