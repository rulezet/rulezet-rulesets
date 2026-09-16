rule TTP_XOR_WriteProcessMemory_6c74 {
  strings:
    $key_6c74 = { 3b 06 [2] 09 24 [2] 0f 11 [2] 21 11 [2] 1e 0d }

  condition:
    any of them
}