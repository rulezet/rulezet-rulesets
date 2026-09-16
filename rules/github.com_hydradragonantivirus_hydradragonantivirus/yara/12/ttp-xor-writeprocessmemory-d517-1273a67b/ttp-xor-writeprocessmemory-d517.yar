rule TTP_XOR_WriteProcessMemory_d517 {
  strings:
    $key_d517 = { 82 65 [2] b0 47 [2] b6 72 [2] 98 72 [2] a7 6e }

  condition:
    any of them
}