rule TTP_XOR_WriteProcessMemory_04be {
  strings:
    $key_04be = { 53 cc [2] 61 ee [2] 67 db [2] 49 db [2] 76 c7 }

  condition:
    any of them
}