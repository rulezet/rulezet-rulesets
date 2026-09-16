rule TTP_XOR_WriteProcessMemory_d67a {
  strings:
    $key_d67a = { 81 08 [2] b3 2a [2] b5 1f [2] 9b 1f [2] a4 03 }

  condition:
    any of them
}