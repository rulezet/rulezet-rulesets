rule TTP_XOR_WriteProcessMemory_fa33 {
  strings:
    $key_fa33 = { ad 41 [2] 9f 63 [2] 99 56 [2] b7 56 [2] 88 4a }

  condition:
    any of them
}