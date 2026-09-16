rule TTP_XOR_WriteProcessMemory_6c7f {
  strings:
    $key_6c7f = { 3b 0d [2] 09 2f [2] 0f 1a [2] 21 1a [2] 1e 06 }

  condition:
    any of them
}