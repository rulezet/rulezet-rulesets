rule TTP_XOR_WriteProcessMemory_617d {
  strings:
    $key_617d = { 36 0f [2] 04 2d [2] 02 18 [2] 2c 18 [2] 13 04 }

  condition:
    any of them
}