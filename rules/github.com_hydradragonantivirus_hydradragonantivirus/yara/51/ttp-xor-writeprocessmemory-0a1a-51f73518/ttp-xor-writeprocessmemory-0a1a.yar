rule TTP_XOR_WriteProcessMemory_0a1a {
  strings:
    $key_0a1a = { 5d 68 [2] 6f 4a [2] 69 7f [2] 47 7f [2] 78 63 }

  condition:
    any of them
}