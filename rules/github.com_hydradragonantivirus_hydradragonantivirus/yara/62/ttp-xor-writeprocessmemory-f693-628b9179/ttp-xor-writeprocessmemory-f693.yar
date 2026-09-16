rule TTP_XOR_WriteProcessMemory_f693 {
  strings:
    $key_f693 = { a1 e1 [2] 93 c3 [2] 95 f6 [2] bb f6 [2] 84 ea }

  condition:
    any of them
}