rule TTP_XOR_WriteProcessMemory_c6dd {
  strings:
    $key_c6dd = { 91 af [2] a3 8d [2] a5 b8 [2] 8b b8 [2] b4 a4 }

  condition:
    any of them
}