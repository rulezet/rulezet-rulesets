rule TTP_XOR_WriteProcessMemory_f474 {
  strings:
    $key_f474 = { a3 06 [2] 91 24 [2] 97 11 [2] b9 11 [2] 86 0d }

  condition:
    any of them
}