rule TTP_XOR_WriteProcessMemory_4fc8 {
  strings:
    $key_4fc8 = { 18 ba [2] 2a 98 [2] 2c ad [2] 02 ad [2] 3d b1 }

  condition:
    any of them
}