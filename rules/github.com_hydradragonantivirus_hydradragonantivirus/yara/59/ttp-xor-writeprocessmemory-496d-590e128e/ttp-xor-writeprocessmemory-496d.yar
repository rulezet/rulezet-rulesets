rule TTP_XOR_WriteProcessMemory_496d {
  strings:
    $key_496d = { 1e 1f [2] 2c 3d [2] 2a 08 [2] 04 08 [2] 3b 14 }

  condition:
    any of them
}