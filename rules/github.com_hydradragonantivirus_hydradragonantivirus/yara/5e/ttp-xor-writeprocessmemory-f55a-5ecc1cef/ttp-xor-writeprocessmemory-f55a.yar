rule TTP_XOR_WriteProcessMemory_f55a {
  strings:
    $key_f55a = { a2 28 [2] 90 0a [2] 96 3f [2] b8 3f [2] 87 23 }

  condition:
    any of them
}