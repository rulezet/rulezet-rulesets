rule TTP_XOR_WriteProcessMemory_7c74 {
  strings:
    $key_7c74 = { 2b 06 [2] 19 24 [2] 1f 11 [2] 31 11 [2] 0e 0d }

  condition:
    any of them
}