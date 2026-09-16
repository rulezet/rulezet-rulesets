rule TTP_XOR_WriteProcessMemory_c60f {
  strings:
    $key_c60f = { 91 7d [2] a3 5f [2] a5 6a [2] 8b 6a [2] b4 76 }

  condition:
    any of them
}