rule TTP_XOR_WriteProcessMemory_6c2f {
  strings:
    $key_6c2f = { 3b 5d [2] 09 7f [2] 0f 4a [2] 21 4a [2] 1e 56 }

  condition:
    any of them
}