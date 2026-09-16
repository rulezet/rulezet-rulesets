rule TTP_XOR_WriteProcessMemory_c45a {
  strings:
    $key_c45a = { 93 28 [2] a1 0a [2] a7 3f [2] 89 3f [2] b6 23 }

  condition:
    any of them
}