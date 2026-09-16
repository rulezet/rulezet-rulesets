rule TTP_XOR_WriteProcessMemory_fa24 {
  strings:
    $key_fa24 = { ad 56 [2] 9f 74 [2] 99 41 [2] b7 41 [2] 88 5d }

  condition:
    any of them
}