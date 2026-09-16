rule TTP_XOR_WriteProcessMemory_c4ed {
  strings:
    $key_c4ed = { 93 9f [2] a1 bd [2] a7 88 [2] 89 88 [2] b6 94 }

  condition:
    any of them
}