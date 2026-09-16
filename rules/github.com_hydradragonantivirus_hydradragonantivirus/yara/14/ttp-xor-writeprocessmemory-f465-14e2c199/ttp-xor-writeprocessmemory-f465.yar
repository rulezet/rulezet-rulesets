rule TTP_XOR_WriteProcessMemory_f465 {
  strings:
    $key_f465 = { a3 17 [2] 91 35 [2] 97 00 [2] b9 00 [2] 86 1c }

  condition:
    any of them
}