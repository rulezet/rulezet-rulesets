rule TTP_XOR_WriteProcessMemory_c417 {
  strings:
    $key_c417 = { 93 65 [2] a1 47 [2] a7 72 [2] 89 72 [2] b6 6e }

  condition:
    any of them
}