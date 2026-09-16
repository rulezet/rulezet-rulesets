rule TTP_XOR_WriteProcessMemory_fa0a {
  strings:
    $key_fa0a = { ad 78 [2] 9f 5a [2] 99 6f [2] b7 6f [2] 88 73 }

  condition:
    any of them
}