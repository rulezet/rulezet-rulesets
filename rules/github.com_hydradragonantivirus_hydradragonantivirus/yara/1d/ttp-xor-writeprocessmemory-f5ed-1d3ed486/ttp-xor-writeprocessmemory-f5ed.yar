rule TTP_XOR_WriteProcessMemory_f5ed {
  strings:
    $key_f5ed = { a2 9f [2] 90 bd [2] 96 88 [2] b8 88 [2] 87 94 }

  condition:
    any of them
}