rule TTP_XOR_WriteProcessMemory_0c70 {
  strings:
    $key_0c70 = { 5b 02 [2] 69 20 [2] 6f 15 [2] 41 15 [2] 7e 09 }

  condition:
    any of them
}