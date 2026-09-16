rule TTP_XOR_WriteProcessMemory_0d28 {
  strings:
    $key_0d28 = { 5a 5a [2] 68 78 [2] 6e 4d [2] 40 4d [2] 7f 51 }

  condition:
    any of them
}