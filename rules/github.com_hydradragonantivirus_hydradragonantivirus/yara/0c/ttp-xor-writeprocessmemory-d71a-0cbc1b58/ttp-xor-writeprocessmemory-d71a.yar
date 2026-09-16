rule TTP_XOR_WriteProcessMemory_d71a {
  strings:
    $key_d71a = { 80 68 [2] b2 4a [2] b4 7f [2] 9a 7f [2] a5 63 }

  condition:
    any of them
}