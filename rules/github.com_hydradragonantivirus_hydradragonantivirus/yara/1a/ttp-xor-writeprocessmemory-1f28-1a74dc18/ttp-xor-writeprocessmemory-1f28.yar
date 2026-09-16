rule TTP_XOR_WriteProcessMemory_1f28 {
  strings:
    $key_1f28 = { 48 5a [2] 7a 78 [2] 7c 4d [2] 52 4d [2] 6d 51 }

  condition:
    any of them
}