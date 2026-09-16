rule TTP_XOR_WriteProcessMemory_f433 {
  strings:
    $key_f433 = { a3 41 [2] 91 63 [2] 97 56 [2] b9 56 [2] 86 4a }

  condition:
    any of them
}