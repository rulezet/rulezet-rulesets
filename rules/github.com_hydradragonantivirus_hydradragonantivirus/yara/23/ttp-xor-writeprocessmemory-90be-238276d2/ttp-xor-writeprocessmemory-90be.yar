rule TTP_XOR_WriteProcessMemory_90be {
  strings:
    $key_90be = { c7 cc [2] f5 ee [2] f3 db [2] dd db [2] e2 c7 }

  condition:
    any of them
}