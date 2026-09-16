rule TTP_XOR_WriteProcessMemory_c2ed {
  strings:
    $key_c2ed = { 95 9f [2] a7 bd [2] a1 88 [2] 8f 88 [2] b0 94 }

  condition:
    any of them
}