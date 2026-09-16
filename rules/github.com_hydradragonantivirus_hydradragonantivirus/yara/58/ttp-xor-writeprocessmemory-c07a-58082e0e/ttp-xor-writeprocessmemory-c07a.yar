rule TTP_XOR_WriteProcessMemory_c07a {
  strings:
    $key_c07a = { 97 08 [2] a5 2a [2] a3 1f [2] 8d 1f [2] b2 03 }

  condition:
    any of them
}