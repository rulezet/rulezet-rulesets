rule TTP_XOR_WriteProcessMemory_496f {
  strings:
    $key_496f = { 1e 1d [2] 2c 3f [2] 2a 0a [2] 04 0a [2] 3b 16 }

  condition:
    any of them
}