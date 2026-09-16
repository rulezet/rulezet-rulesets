rule TTP_XOR_WriteProcessMemory_7a20 {
  strings:
    $key_7a20 = { 2d 52 [2] 1f 70 [2] 19 45 [2] 37 45 [2] 08 59 }

  condition:
    any of them
}