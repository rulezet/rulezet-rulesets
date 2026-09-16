rule TTP_XOR_WriteProcessMemory_c7ed {
  strings:
    $key_c7ed = { 90 9f [2] a2 bd [2] a4 88 [2] 8a 88 [2] b5 94 }

  condition:
    any of them
}