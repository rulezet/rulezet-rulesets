rule TTP_XOR_WriteProcessMemory_c25a {
  strings:
    $key_c25a = { 95 28 [2] a7 0a [2] a1 3f [2] 8f 3f [2] b0 23 }

  condition:
    any of them
}