rule TTP_XOR_WriteProcessMemory_f402 {
  strings:
    $key_f402 = { a3 70 [2] 91 52 [2] 97 67 [2] b9 67 [2] 86 7b }

  condition:
    any of them
}