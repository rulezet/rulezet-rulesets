rule TTP_XOR_WriteProcessMemory_d36a {
  strings:
    $key_d36a = { 84 18 [2] b6 3a [2] b0 0f [2] 9e 0f [2] a1 13 }

  condition:
    any of them
}