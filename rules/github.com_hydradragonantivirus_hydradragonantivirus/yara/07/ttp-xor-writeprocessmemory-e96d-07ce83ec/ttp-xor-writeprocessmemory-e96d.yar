rule TTP_XOR_WriteProcessMemory_e96d {
  strings:
    $key_e96d = { be 1f [2] 8c 3d [2] 8a 08 [2] a4 08 [2] 9b 14 }

  condition:
    any of them
}