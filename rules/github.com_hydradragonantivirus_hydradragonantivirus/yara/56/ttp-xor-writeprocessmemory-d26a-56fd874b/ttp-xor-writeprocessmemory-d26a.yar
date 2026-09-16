rule TTP_XOR_WriteProcessMemory_d26a {
  strings:
    $key_d26a = { 85 18 [2] b7 3a [2] b1 0f [2] 9f 0f [2] a0 13 }

  condition:
    any of them
}