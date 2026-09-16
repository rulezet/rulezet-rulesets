rule TTP_XOR_WriteProcessMemory_d7ed {
  strings:
    $key_d7ed = { 80 9f [2] b2 bd [2] b4 88 [2] 9a 88 [2] a5 94 }

  condition:
    any of them
}