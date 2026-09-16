rule TTP_XOR_WriteProcessMemory_f517 {
  strings:
    $key_f517 = { a2 65 [2] 90 47 [2] 96 72 [2] b8 72 [2] 87 6e }

  condition:
    any of them
}