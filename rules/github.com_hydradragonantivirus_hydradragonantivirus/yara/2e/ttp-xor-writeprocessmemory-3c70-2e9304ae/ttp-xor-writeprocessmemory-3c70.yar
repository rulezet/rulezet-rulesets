rule TTP_XOR_WriteProcessMemory_3c70 {
  strings:
    $key_3c70 = { 6b 02 [2] 59 20 [2] 5f 15 [2] 71 15 [2] 4e 09 }

  condition:
    any of them
}