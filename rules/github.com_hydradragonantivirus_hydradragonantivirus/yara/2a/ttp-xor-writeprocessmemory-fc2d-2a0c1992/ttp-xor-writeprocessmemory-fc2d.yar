rule TTP_XOR_WriteProcessMemory_fc2d {
  strings:
    $key_fc2d = { ab 5f [2] 99 7d [2] 9f 48 [2] b1 48 [2] 8e 54 }

  condition:
    any of them
}