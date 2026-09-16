rule TTP_XOR_WriteProcessMemory_3c28 {
  strings:
    $key_3c28 = { 6b 5a [2] 59 78 [2] 5f 4d [2] 71 4d [2] 4e 51 }

  condition:
    any of them
}