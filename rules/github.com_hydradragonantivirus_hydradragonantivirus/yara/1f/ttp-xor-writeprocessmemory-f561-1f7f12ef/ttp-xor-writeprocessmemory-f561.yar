rule TTP_XOR_WriteProcessMemory_f561 {
  strings:
    $key_f561 = { a2 13 [2] 90 31 [2] 96 04 [2] b8 04 [2] 87 18 }

  condition:
    any of them
}