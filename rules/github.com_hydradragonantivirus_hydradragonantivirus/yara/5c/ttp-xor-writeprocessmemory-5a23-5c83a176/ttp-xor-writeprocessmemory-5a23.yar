rule TTP_XOR_WriteProcessMemory_5a23 {
  strings:
    $key_5a23 = { 0d 51 [2] 3f 73 [2] 39 46 [2] 17 46 [2] 28 5a }

  condition:
    any of them
}