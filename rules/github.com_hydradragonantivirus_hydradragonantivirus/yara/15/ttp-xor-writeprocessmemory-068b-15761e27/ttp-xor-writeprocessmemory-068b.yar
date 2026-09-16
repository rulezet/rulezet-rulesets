rule TTP_XOR_WriteProcessMemory_068b {
  strings:
    $key_068b = { 51 f9 [2] 63 db [2] 65 ee [2] 4b ee [2] 74 f2 }

  condition:
    any of them
}