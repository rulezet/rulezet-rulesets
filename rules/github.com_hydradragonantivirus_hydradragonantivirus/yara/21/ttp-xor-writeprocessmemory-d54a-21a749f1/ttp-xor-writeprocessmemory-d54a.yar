rule TTP_XOR_WriteProcessMemory_d54a {
  strings:
    $key_d54a = { 82 38 [2] b0 1a [2] b6 2f [2] 98 2f [2] a7 33 }

  condition:
    any of them
}