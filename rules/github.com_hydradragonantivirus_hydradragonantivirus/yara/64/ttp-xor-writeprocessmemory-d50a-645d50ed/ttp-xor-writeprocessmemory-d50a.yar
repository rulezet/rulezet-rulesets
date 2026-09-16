rule TTP_XOR_WriteProcessMemory_d50a {
  strings:
    $key_d50a = { 82 78 [2] b0 5a [2] b6 6f [2] 98 6f [2] a7 73 }

  condition:
    any of them
}