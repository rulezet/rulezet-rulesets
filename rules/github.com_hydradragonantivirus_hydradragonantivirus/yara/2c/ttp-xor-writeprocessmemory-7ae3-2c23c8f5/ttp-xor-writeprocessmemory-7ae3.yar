rule TTP_XOR_WriteProcessMemory_7ae3 {
  strings:
    $key_7ae3 = { 2d 91 [2] 1f b3 [2] 19 86 [2] 37 86 [2] 08 9a }

  condition:
    any of them
}