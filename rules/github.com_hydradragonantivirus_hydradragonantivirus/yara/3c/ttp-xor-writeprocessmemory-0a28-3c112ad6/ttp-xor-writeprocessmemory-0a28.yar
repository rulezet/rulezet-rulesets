rule TTP_XOR_WriteProcessMemory_0a28 {
  strings:
    $key_0a28 = { 5d 5a [2] 6f 78 [2] 69 4d [2] 47 4d [2] 78 51 }

  condition:
    any of them
}