rule TTP_XOR_WriteProcessMemory_c00a {
  strings:
    $key_c00a = { 97 78 [2] a5 5a [2] a3 6f [2] 8d 6f [2] b2 73 }

  condition:
    any of them
}