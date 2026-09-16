rule TTP_XOR_WriteProcessMemory_c67a {
  strings:
    $key_c67a = { 91 08 [2] a3 2a [2] a5 1f [2] 8b 1f [2] b4 03 }

  condition:
    any of them
}