rule TTP_XOR_WriteProcessMemory_f52a {
  strings:
    $key_f52a = { a2 58 [2] 90 7a [2] 96 4f [2] b8 4f [2] 87 53 }

  condition:
    any of them
}