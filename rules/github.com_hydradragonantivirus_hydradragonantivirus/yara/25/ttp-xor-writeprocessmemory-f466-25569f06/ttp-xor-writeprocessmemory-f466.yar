rule TTP_XOR_WriteProcessMemory_f466 {
  strings:
    $key_f466 = { a3 14 [2] 91 36 [2] 97 03 [2] b9 03 [2] 86 1f }

  condition:
    any of them
}