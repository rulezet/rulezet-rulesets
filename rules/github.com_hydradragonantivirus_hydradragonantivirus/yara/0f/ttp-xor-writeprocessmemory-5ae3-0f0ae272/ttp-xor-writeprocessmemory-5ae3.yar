rule TTP_XOR_WriteProcessMemory_5ae3 {
  strings:
    $key_5ae3 = { 0d 91 [2] 3f b3 [2] 39 86 [2] 17 86 [2] 28 9a }

  condition:
    any of them
}