rule TTP_XOR_WriteProcessMemory_d17a {
  strings:
    $key_d17a = { 86 08 [2] b4 2a [2] b2 1f [2] 9c 1f [2] a3 03 }

  condition:
    any of them
}