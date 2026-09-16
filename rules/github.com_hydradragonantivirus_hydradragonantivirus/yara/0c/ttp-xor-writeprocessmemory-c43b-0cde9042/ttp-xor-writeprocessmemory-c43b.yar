rule TTP_XOR_WriteProcessMemory_c43b {
  strings:
    $key_c43b = { 93 49 [2] a1 6b [2] a7 5e [2] 89 5e [2] b6 42 }

  condition:
    any of them
}