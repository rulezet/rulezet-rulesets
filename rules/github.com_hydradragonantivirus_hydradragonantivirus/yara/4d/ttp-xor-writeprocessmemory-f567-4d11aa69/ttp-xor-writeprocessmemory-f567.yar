rule TTP_XOR_WriteProcessMemory_f567 {
  strings:
    $key_f567 = { a2 15 [2] 90 37 [2] 96 02 [2] b8 02 [2] 87 1e }

  condition:
    any of them
}