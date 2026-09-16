rule TTP_XOR_WriteProcessMemory_c50a {
  strings:
    $key_c50a = { 92 78 [2] a0 5a [2] a6 6f [2] 88 6f [2] b7 73 }

  condition:
    any of them
}