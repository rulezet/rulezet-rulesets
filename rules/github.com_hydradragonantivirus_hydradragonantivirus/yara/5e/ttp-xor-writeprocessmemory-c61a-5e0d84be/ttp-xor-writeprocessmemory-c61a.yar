rule TTP_XOR_WriteProcessMemory_c61a {
  strings:
    $key_c61a = { 91 68 [2] a3 4a [2] a5 7f [2] 8b 7f [2] b4 63 }

  condition:
    any of them
}