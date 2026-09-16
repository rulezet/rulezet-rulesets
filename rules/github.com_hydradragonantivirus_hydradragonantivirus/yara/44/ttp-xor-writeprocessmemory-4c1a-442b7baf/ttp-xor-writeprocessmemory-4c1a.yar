rule TTP_XOR_WriteProcessMemory_4c1a {
  strings:
    $key_4c1a = { 1b 68 [2] 29 4a [2] 2f 7f [2] 01 7f [2] 3e 63 }

  condition:
    any of them
}