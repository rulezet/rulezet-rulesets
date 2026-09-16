rule TTP_XOR_WriteProcessMemory_4f3f {
  strings:
    $key_4f3f = { 18 4d [2] 2a 6f [2] 2c 5a [2] 02 5a [2] 3d 46 }

  condition:
    any of them
}