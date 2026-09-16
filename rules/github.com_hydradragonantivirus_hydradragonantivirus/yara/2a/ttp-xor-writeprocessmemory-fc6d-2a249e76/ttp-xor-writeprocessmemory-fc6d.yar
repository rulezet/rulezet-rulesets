rule TTP_XOR_WriteProcessMemory_fc6d {
  strings:
    $key_fc6d = { ab 1f [2] 99 3d [2] 9f 08 [2] b1 08 [2] 8e 14 }

  condition:
    any of them
}