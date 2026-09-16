rule TTP_XOR_WriteProcessMemory_6928 {
  strings:
    $key_6928 = { 3e 5a [2] 0c 78 [2] 0a 4d [2] 24 4d [2] 1b 51 }

  condition:
    any of them
}