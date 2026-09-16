rule TTP_XOR_WriteProcessMemory_626d {
  strings:
    $key_626d = { 35 1f [2] 07 3d [2] 01 08 [2] 2f 08 [2] 10 14 }

  condition:
    any of them
}