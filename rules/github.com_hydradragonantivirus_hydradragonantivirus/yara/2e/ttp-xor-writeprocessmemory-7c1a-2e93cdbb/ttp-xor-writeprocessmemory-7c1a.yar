rule TTP_XOR_WriteProcessMemory_7c1a {
  strings:
    $key_7c1a = { 2b 68 [2] 19 4a [2] 1f 7f [2] 31 7f [2] 0e 63 }

  condition:
    any of them
}