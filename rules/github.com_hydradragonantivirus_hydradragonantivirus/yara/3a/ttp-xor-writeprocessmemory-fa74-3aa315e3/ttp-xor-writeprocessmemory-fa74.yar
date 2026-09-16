rule TTP_XOR_WriteProcessMemory_fa74 {
  strings:
    $key_fa74 = { ad 06 [2] 9f 24 [2] 99 11 [2] b7 11 [2] 88 0d }

  condition:
    any of them
}