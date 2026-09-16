rule TTP_XOR_WriteProcessMemory_d62a {
  strings:
    $key_d62a = { 81 58 [2] b3 7a [2] b5 4f [2] 9b 4f [2] a4 53 }

  condition:
    any of them
}