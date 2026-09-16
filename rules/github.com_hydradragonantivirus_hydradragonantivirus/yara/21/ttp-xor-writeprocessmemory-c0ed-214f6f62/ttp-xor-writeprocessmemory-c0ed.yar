rule TTP_XOR_WriteProcessMemory_c0ed {
  strings:
    $key_c0ed = { 97 9f [2] a5 bd [2] a3 88 [2] 8d 88 [2] b2 94 }

  condition:
    any of them
}