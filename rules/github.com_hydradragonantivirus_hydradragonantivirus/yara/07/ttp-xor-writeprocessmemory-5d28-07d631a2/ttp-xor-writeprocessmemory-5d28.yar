rule TTP_XOR_WriteProcessMemory_5d28 {
  strings:
    $key_5d28 = { 0a 5a [2] 38 78 [2] 3e 4d [2] 10 4d [2] 2f 51 }

  condition:
    any of them
}