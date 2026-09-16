rule TTP_XOR_WriteProcessMemory_5a01 {
  strings:
    $key_5a01 = { 0d 73 [2] 3f 51 [2] 39 64 [2] 17 64 [2] 28 78 }

  condition:
    any of them
}