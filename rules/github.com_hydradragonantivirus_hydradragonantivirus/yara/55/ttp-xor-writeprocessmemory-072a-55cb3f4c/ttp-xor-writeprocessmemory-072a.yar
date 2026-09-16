rule TTP_XOR_WriteProcessMemory_072a {
  strings:
    $key_072a = { 50 58 [2] 62 7a [2] 64 4f [2] 4a 4f [2] 75 53 }

  condition:
    any of them
}