rule TTP_XOR_WriteProcessMemory_c46a {
  strings:
    $key_c46a = { 93 18 [2] a1 3a [2] a7 0f [2] 89 0f [2] b6 13 }

  condition:
    any of them
}