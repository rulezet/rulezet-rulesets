rule TTP_XOR_WriteProcessMemory_0a0a {
  strings:
    $key_0a0a = { 5d 78 [2] 6f 5a [2] 69 6f [2] 47 6f [2] 78 73 }

  condition:
    any of them
}