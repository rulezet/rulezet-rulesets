rule TTP_XOR_WriteProcessMemory_1c70 {
  strings:
    $key_1c70 = { 4b 02 [2] 79 20 [2] 7f 15 [2] 51 15 [2] 6e 09 }

  condition:
    any of them
}