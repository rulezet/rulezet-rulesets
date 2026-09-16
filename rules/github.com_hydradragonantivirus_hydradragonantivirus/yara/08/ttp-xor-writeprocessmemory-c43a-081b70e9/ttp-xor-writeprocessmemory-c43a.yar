rule TTP_XOR_WriteProcessMemory_c43a {
  strings:
    $key_c43a = { 93 48 [2] a1 6a [2] a7 5f [2] 89 5f [2] b6 43 }

  condition:
    any of them
}