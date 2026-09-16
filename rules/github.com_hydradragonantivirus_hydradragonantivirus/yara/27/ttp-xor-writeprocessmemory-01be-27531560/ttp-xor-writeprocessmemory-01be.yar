rule TTP_XOR_WriteProcessMemory_01be {
  strings:
    $key_01be = { 56 cc [2] 64 ee [2] 62 db [2] 4c db [2] 73 c7 }

  condition:
    any of them
}