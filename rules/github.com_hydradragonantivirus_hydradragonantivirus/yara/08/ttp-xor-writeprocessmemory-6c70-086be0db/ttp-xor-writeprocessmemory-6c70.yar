rule TTP_XOR_WriteProcessMemory_6c70 {
  strings:
    $key_6c70 = { 3b 02 [2] 09 20 [2] 0f 15 [2] 21 15 [2] 1e 09 }

  condition:
    any of them
}