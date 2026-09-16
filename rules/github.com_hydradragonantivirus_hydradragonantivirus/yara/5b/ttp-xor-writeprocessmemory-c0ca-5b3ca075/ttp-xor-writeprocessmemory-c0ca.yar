rule TTP_XOR_WriteProcessMemory_c0ca {
  strings:
    $key_c0ca = { 97 b8 [2] a5 9a [2] a3 af [2] 8d af [2] b2 b3 }

  condition:
    any of them
}