rule TTP_XOR_WriteProcessMemory_7c70 {
  strings:
    $key_7c70 = { 2b 02 [2] 19 20 [2] 1f 15 [2] 31 15 [2] 0e 09 }

  condition:
    any of them
}