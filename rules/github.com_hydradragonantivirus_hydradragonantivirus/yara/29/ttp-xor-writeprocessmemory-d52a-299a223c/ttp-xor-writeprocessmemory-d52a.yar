rule TTP_XOR_WriteProcessMemory_d52a {
  strings:
    $key_d52a = { 82 58 [2] b0 7a [2] b6 4f [2] 98 4f [2] a7 53 }

  condition:
    any of them
}