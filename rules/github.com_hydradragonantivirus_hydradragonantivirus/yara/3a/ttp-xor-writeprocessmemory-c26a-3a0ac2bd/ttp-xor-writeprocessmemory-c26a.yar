rule TTP_XOR_WriteProcessMemory_c26a {
  strings:
    $key_c26a = { 95 18 [2] a7 3a [2] a1 0f [2] 8f 0f [2] b0 13 }

  condition:
    any of them
}