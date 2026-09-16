rule TTP_XOR_WriteProcessMemory_fa1a {
  strings:
    $key_fa1a = { ad 68 [2] 9f 4a [2] 99 7f [2] b7 7f [2] 88 63 }

  condition:
    any of them
}