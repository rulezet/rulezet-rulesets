rule TTP_XOR_WriteProcessMemory_54be {
  strings:
    $key_54be = { 03 cc [2] 31 ee [2] 37 db [2] 19 db [2] 26 c7 }

  condition:
    any of them
}