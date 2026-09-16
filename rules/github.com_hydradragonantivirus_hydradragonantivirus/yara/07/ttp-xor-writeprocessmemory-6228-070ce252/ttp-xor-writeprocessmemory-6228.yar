rule TTP_XOR_WriteProcessMemory_6228 {
  strings:
    $key_6228 = { 35 5a [2] 07 78 [2] 01 4d [2] 2f 4d [2] 10 51 }

  condition:
    any of them
}