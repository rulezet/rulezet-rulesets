rule TTP_XOR_WriteProcessMemory_fc58 {
  strings:
    $key_fc58 = { ab 2a [2] 99 08 [2] 9f 3d [2] b1 3d [2] 8e 21 }

  condition:
    any of them
}