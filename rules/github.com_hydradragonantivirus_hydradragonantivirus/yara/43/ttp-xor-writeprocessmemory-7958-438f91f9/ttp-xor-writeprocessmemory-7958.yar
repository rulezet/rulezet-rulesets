rule TTP_XOR_WriteProcessMemory_7958 {
  strings:
    $key_7958 = { 2e 2a [2] 1c 08 [2] 1a 3d [2] 34 3d [2] 0b 21 }

  condition:
    any of them
}