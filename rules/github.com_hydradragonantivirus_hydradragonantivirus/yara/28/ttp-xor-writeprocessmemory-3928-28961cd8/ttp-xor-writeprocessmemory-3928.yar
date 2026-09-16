rule TTP_XOR_WriteProcessMemory_3928 {
  strings:
    $key_3928 = { 6e 5a [2] 5c 78 [2] 5a 4d [2] 74 4d [2] 4b 51 }

  condition:
    any of them
}