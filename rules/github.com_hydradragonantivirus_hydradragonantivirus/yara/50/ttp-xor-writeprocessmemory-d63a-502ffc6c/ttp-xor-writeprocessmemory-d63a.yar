rule TTP_XOR_WriteProcessMemory_d63a {
  strings:
    $key_d63a = { 81 48 [2] b3 6a [2] b5 5f [2] 9b 5f [2] a4 43 }

  condition:
    any of them
}