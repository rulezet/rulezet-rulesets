rule TTP_XOR_WriteProcessMemory_4528 {
  strings:
    $key_4528 = { 12 5a [2] 20 78 [2] 26 4d [2] 08 4d [2] 37 51 }

  condition:
    any of them
}