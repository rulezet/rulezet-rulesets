rule TTP_XOR_WriteProcessMemory_e63a {
  strings:
    $key_e63a = { b1 48 [2] 83 6a [2] 85 5f [2] ab 5f [2] 94 43 }

  condition:
    any of them
}