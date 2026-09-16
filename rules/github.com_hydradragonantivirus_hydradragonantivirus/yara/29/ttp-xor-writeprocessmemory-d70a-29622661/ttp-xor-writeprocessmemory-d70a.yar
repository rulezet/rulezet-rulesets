rule TTP_XOR_WriteProcessMemory_d70a {
  strings:
    $key_d70a = { 80 78 [2] b2 5a [2] b4 6f [2] 9a 6f [2] a5 73 }

  condition:
    any of them
}