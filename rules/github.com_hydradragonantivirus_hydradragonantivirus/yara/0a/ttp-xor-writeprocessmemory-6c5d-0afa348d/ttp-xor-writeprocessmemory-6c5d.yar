rule TTP_XOR_WriteProcessMemory_6c5d {
  strings:
    $key_6c5d = { 3b 2f [2] 09 0d [2] 0f 38 [2] 21 38 [2] 1e 24 }

  condition:
    any of them
}