rule TTP_XOR_WriteProcessMemory_c70a {
  strings:
    $key_c70a = { 90 78 [2] a2 5a [2] a4 6f [2] 8a 6f [2] b5 73 }

  condition:
    any of them
}