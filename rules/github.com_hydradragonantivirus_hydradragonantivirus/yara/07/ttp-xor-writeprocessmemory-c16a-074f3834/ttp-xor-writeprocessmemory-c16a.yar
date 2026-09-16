rule TTP_XOR_WriteProcessMemory_c16a {
  strings:
    $key_c16a = { 96 18 [2] a4 3a [2] a2 0f [2] 8c 0f [2] b3 13 }

  condition:
    any of them
}