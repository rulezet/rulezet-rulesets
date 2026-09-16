rule TTP_XOR_WriteProcessMemory_c06a {
  strings:
    $key_c06a = { 97 18 [2] a5 3a [2] a3 0f [2] 8d 0f [2] b2 13 }

  condition:
    any of them
}