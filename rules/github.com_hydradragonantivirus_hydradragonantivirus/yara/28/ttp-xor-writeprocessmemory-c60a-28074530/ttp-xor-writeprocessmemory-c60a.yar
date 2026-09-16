rule TTP_XOR_WriteProcessMemory_c60a {
  strings:
    $key_c60a = { 91 78 [2] a3 5a [2] a5 6f [2] 8b 6f [2] b4 73 }

  condition:
    any of them
}