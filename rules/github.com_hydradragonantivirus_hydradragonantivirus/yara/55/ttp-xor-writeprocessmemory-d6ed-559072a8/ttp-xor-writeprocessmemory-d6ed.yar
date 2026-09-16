rule TTP_XOR_WriteProcessMemory_d6ed {
  strings:
    $key_d6ed = { 81 9f [2] b3 bd [2] b5 88 [2] 9b 88 [2] a4 94 }

  condition:
    any of them
}