rule TTP_XOR_WriteProcessMemory_736d {
  strings:
    $key_736d = { 24 1f [2] 16 3d [2] 10 08 [2] 3e 08 [2] 01 14 }

  condition:
    any of them
}