rule TTP_XOR_WriteProcessMemory_f717 {
  strings:
    $key_f717 = { a0 65 [2] 92 47 [2] 94 72 [2] ba 72 [2] 85 6e }

  condition:
    any of them
}