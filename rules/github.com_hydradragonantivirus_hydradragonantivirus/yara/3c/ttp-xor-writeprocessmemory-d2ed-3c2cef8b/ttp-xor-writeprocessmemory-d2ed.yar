rule TTP_XOR_WriteProcessMemory_d2ed {
  strings:
    $key_d2ed = { 85 9f [2] b7 bd [2] b1 88 [2] 9f 88 [2] a0 94 }

  condition:
    any of them
}