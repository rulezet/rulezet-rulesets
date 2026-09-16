rule TTP_XOR_WriteProcessMemory_495f {
  strings:
    $key_495f = { 1e 2d [2] 2c 0f [2] 2a 3a [2] 04 3a [2] 3b 26 }

  condition:
    any of them
}