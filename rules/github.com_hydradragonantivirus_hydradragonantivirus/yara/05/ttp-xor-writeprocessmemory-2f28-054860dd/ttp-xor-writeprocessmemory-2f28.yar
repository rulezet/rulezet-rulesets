rule TTP_XOR_WriteProcessMemory_2f28 {
  strings:
    $key_2f28 = { 78 5a [2] 4a 78 [2] 4c 4d [2] 62 4d [2] 5d 51 }

  condition:
    any of them
}