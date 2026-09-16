rule TTP_XOR_WriteProcessMemory_fc0d {
  strings:
    $key_fc0d = { ab 7f [2] 99 5d [2] 9f 68 [2] b1 68 [2] 8e 74 }

  condition:
    any of them
}