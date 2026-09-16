rule TTP_XOR_WriteProcessMemory_6c1f {
  strings:
    $key_6c1f = { 3b 6d [2] 09 4f [2] 0f 7a [2] 21 7a [2] 1e 66 }

  condition:
    any of them
}