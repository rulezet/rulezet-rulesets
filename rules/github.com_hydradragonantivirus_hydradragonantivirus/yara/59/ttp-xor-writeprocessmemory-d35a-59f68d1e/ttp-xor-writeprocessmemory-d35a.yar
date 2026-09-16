rule TTP_XOR_WriteProcessMemory_d35a {
  strings:
    $key_d35a = { 84 28 [2] b6 0a [2] b0 3f [2] 9e 3f [2] a1 23 }

  condition:
    any of them
}