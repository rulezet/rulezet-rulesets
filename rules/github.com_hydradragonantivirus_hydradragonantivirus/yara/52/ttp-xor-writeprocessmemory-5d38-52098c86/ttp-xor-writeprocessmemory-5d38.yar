rule TTP_XOR_WriteProcessMemory_5d38 {
  strings:
    $key_5d38 = { 0a 4a [2] 38 68 [2] 3e 5d [2] 10 5d [2] 2f 41 }

  condition:
    any of them
}