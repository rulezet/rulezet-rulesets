rule TTP_XOR_WriteProcessMemory_f233 {
  strings:
    $key_f233 = { a5 41 [2] 97 63 [2] 91 56 [2] bf 56 [2] 80 4a }

  condition:
    any of them
}