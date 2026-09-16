rule TTP_XOR_WriteProcessMemory_d0ca {
  strings:
    $key_d0ca = { 87 b8 [2] b5 9a [2] b3 af [2] 9d af [2] a2 b3 }

  condition:
    any of them
}