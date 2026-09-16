rule TTP_XOR_WriteProcessMemory_f547 {
  strings:
    $key_f547 = { a2 35 [2] 90 17 [2] 96 22 [2] b8 22 [2] 87 3e }

  condition:
    any of them
}