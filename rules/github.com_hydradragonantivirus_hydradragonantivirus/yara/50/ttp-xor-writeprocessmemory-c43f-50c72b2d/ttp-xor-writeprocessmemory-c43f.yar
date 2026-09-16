rule TTP_XOR_WriteProcessMemory_c43f {
  strings:
    $key_c43f = { 93 4d [2] a1 6f [2] a7 5a [2] 89 5a [2] b6 46 }

  condition:
    any of them
}