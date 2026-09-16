rule TTP_XOR_WriteProcessMemory_496c {
  strings:
    $key_496c = { 1e 1e [2] 2c 3c [2] 2a 09 [2] 04 09 [2] 3b 15 }

  condition:
    any of them
}