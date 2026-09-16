rule TTP_XOR_WriteProcessMemory_d56a {
  strings:
    $key_d56a = { 82 18 [2] b0 3a [2] b6 0f [2] 98 0f [2] a7 13 }

  condition:
    any of them
}