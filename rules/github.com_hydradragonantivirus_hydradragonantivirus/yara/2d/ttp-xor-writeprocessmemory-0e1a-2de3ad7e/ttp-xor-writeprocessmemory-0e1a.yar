rule TTP_XOR_WriteProcessMemory_0e1a {
  strings:
    $key_0e1a = { 59 68 [2] 6b 4a [2] 6d 7f [2] 43 7f [2] 7c 63 }

  condition:
    any of them
}