rule TTP_XOR_WriteProcessMemory_6c4a {
  strings:
    $key_6c4a = { 3b 38 [2] 09 1a [2] 0f 2f [2] 21 2f [2] 1e 33 }

  condition:
    any of them
}