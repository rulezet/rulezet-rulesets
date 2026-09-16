rule TTP_XOR_WriteProcessMemory_fa6a {
  strings:
    $key_fa6a = { ad 18 [2] 9f 3a [2] 99 0f [2] b7 0f [2] 88 13 }

  condition:
    any of them
}