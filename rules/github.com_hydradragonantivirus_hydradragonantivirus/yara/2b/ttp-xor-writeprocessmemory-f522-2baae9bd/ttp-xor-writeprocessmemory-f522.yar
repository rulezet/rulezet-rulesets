rule TTP_XOR_WriteProcessMemory_f522 {
  strings:
    $key_f522 = { a2 50 [2] 90 72 [2] 96 47 [2] b8 47 [2] 87 5b }

  condition:
    any of them
}