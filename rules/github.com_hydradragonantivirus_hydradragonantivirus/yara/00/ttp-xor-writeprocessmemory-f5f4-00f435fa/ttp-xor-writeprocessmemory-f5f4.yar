rule TTP_XOR_WriteProcessMemory_f5f4 {
  strings:
    $key_f5f4 = { a2 86 [2] 90 a4 [2] 96 91 [2] b8 91 [2] 87 8d }

  condition:
    any of them
}