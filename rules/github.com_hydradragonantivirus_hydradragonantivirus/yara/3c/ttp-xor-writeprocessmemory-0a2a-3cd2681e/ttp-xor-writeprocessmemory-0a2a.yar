rule TTP_XOR_WriteProcessMemory_0a2a {
  strings:
    $key_0a2a = { 5d 58 [2] 6f 7a [2] 69 4f [2] 47 4f [2] 78 53 }

  condition:
    any of them
}