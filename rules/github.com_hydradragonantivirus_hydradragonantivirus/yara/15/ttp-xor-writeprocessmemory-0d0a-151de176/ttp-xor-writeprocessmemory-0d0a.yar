rule TTP_XOR_WriteProcessMemory_0d0a {
  strings:
    $key_0d0a = { 5a 78 [2] 68 5a [2] 6e 6f [2] 40 6f [2] 7f 73 }

  condition:
    any of them
}