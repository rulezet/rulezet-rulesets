rule TTP_XOR_WriteProcessMemory_2928 {
  strings:
    $key_2928 = { 7e 5a [2] 4c 78 [2] 4a 4d [2] 64 4d [2] 5b 51 }

  condition:
    any of them
}