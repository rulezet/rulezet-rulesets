rule TTP_XOR_WriteProcessMemory_6c7a {
  strings:
    $key_6c7a = { 3b 08 [2] 09 2a [2] 0f 1f [2] 21 1f [2] 1e 03 }

  condition:
    any of them
}