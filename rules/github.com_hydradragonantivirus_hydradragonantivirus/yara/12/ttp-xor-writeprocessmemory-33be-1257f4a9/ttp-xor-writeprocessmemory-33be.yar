rule TTP_XOR_WriteProcessMemory_33be {
  strings:
    $key_33be = { 64 cc [2] 56 ee [2] 50 db [2] 7e db [2] 41 c7 }

  condition:
    any of them
}