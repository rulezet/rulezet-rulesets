rule TTP_XOR_WriteProcessMemory_f571 {
  strings:
    $key_f571 = { a2 03 [2] 90 21 [2] 96 14 [2] b8 14 [2] 87 08 }

  condition:
    any of them
}