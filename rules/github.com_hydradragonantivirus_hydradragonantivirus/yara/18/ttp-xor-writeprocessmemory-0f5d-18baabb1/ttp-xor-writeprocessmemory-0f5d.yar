rule TTP_XOR_WriteProcessMemory_0f5d {
  strings:
    $key_0f5d = { 58 2f [2] 6a 0d [2] 6c 38 [2] 42 38 [2] 7d 24 }

  condition:
    any of them
}