rule TTP_XOR_WriteProcessMemory_d33a {
  strings:
    $key_d33a = { 84 48 [2] b6 6a [2] b0 5f [2] 9e 5f [2] a1 43 }

  condition:
    any of them
}