rule TTP_XOR_WriteProcessMemory_626a {
  strings:
    $key_626a = { 35 18 [2] 07 3a [2] 01 0f [2] 2f 0f [2] 10 13 }

  condition:
    any of them
}