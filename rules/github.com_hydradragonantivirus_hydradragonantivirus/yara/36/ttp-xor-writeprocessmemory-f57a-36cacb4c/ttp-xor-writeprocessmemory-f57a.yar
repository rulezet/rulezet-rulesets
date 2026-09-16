rule TTP_XOR_WriteProcessMemory_f57a {
  strings:
    $key_f57a = { a2 08 [2] 90 2a [2] 96 1f [2] b8 1f [2] 87 03 }

  condition:
    any of them
}