rule TTP_XOR_WriteProcessMemory_e5ed {
  strings:
    $key_e5ed = { b2 9f [2] 80 bd [2] 86 88 [2] a8 88 [2] 97 94 }

  condition:
    any of them
}