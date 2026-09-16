rule TTP_XOR_WriteProcessMemory_c92a {
  strings:
    $key_c92a = { 9e 58 [2] ac 7a [2] aa 4f [2] 84 4f [2] bb 53 }

  condition:
    any of them
}