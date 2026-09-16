rule TTP_XOR_WriteProcessMemory_0c0a {
  strings:
    $key_0c0a = { 5b 78 [2] 69 5a [2] 6f 6f [2] 41 6f [2] 7e 73 }

  condition:
    any of them
}