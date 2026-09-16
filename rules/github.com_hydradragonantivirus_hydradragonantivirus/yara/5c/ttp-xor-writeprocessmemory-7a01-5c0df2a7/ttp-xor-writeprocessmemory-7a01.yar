rule TTP_XOR_WriteProcessMemory_7a01 {
  strings:
    $key_7a01 = { 2d 73 [2] 1f 51 [2] 19 64 [2] 37 64 [2] 08 78 }

  condition:
    any of them
}