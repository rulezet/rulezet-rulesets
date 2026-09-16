rule TTP_XOR_WriteProcessMemory_796d {
  strings:
    $key_796d = { 2e 1f [2] 1c 3d [2] 1a 08 [2] 34 08 [2] 0b 14 }

  condition:
    any of them
}