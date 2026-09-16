rule TTP_XOR_WriteProcessMemory_d4ed {
  strings:
    $key_d4ed = { 83 9f [2] b1 bd [2] b7 88 [2] 99 88 [2] a6 94 }

  condition:
    any of them
}