rule TTP_XOR_WriteProcessMemory_13be {
  strings:
    $key_13be = { 44 cc [2] 76 ee [2] 70 db [2] 5e db [2] 61 c7 }

  condition:
    any of them
}