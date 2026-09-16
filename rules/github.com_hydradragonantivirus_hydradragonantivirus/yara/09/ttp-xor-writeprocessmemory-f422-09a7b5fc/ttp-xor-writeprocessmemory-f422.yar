rule TTP_XOR_WriteProcessMemory_f422 {
  strings:
    $key_f422 = { a3 50 [2] 91 72 [2] 97 47 [2] b9 47 [2] 86 5b }

  condition:
    any of them
}