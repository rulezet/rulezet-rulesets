rule TTP_XOR_WriteProcessMemory_f5e3 {
  strings:
    $key_f5e3 = { a2 91 [2] 90 b3 [2] 96 86 [2] b8 86 [2] 87 9a }

  condition:
    any of them
}