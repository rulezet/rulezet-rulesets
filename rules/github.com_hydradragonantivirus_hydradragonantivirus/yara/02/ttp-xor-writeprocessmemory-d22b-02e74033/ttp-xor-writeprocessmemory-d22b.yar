rule TTP_XOR_WriteProcessMemory_d22b {
  strings:
    $key_d22b = { 85 59 [2] b7 7b [2] b1 4e [2] 9f 4e [2] a0 52 }

  condition:
    any of them
}