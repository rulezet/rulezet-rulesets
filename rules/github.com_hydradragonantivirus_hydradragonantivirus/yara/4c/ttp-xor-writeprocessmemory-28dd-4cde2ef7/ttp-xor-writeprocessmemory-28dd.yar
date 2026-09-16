rule TTP_XOR_WriteProcessMemory_28dd {
  strings:
    $key_28dd = { 7f af [2] 4d 8d [2] 4b b8 [2] 65 b8 [2] 5a a4 }

  condition:
    any of them
}