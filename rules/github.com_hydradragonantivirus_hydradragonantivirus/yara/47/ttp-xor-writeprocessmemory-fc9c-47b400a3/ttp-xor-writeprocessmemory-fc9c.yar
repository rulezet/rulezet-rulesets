rule TTP_XOR_WriteProcessMemory_fc9c {
  strings:
    $key_fc9c = { ab ee [2] 99 cc [2] 9f f9 [2] b1 f9 [2] 8e e5 }

  condition:
    any of them
}