rule TTP_XOR_WriteProcessMemory_fef4 {
  strings:
    $key_fef4 = { a9 86 [2] 9b a4 [2] 9d 91 [2] b3 91 [2] 8c 8d }

  condition:
    any of them
}