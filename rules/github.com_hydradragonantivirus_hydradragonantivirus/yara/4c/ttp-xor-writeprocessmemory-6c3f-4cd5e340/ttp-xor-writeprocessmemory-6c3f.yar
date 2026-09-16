rule TTP_XOR_WriteProcessMemory_6c3f {
  strings:
    $key_6c3f = { 3b 4d [2] 09 6f [2] 0f 5a [2] 21 5a [2] 1e 46 }

  condition:
    any of them
}