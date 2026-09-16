rule TTP_XOR_WriteProcessMemory_e3ed {
  strings:
    $key_e3ed = { b4 9f [2] 86 bd [2] 80 88 [2] ae 88 [2] 91 94 }

  condition:
    any of them
}