rule TTP_XOR_WriteProcessMemory_d527 {
  strings:
    $key_d527 = { 82 55 [2] b0 77 [2] b6 42 [2] 98 42 [2] a7 5e }

  condition:
    any of them
}