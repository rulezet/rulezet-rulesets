rule TTP_XOR_WriteProcessMemory_fa15 {
  strings:
    $key_fa15 = { ad 67 [2] 9f 45 [2] 99 70 [2] b7 70 [2] 88 6c }

  condition:
    any of them
}