rule TTP_XOR_WriteProcessMemory_0f7d {
  strings:
    $key_0f7d = { 58 0f [2] 6a 2d [2] 6c 18 [2] 42 18 [2] 7d 04 }

  condition:
    any of them
}