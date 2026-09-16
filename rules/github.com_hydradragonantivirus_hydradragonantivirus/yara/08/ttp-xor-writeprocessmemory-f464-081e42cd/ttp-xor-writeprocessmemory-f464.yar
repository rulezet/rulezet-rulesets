rule TTP_XOR_WriteProcessMemory_f464 {
  strings:
    $key_f464 = { a3 16 [2] 91 34 [2] 97 01 [2] b9 01 [2] 86 1d }

  condition:
    any of them
}