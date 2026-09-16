rule TTP_XOR_WriteProcessMemory_c317 {
  strings:
    $key_c317 = { 94 65 [2] a6 47 [2] a0 72 [2] 8e 72 [2] b1 6e }

  condition:
    any of them
}