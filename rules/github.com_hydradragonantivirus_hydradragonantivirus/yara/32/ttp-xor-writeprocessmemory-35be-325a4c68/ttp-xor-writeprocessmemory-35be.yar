rule TTP_XOR_WriteProcessMemory_35be {
  strings:
    $key_35be = { 62 cc [2] 50 ee [2] 56 db [2] 78 db [2] 47 c7 }

  condition:
    any of them
}