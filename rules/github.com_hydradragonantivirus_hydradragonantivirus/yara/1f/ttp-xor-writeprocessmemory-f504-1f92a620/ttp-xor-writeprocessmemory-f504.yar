rule TTP_XOR_WriteProcessMemory_f504 {
  strings:
    $key_f504 = { a2 76 [2] 90 54 [2] 96 61 [2] b8 61 [2] 87 7d }

  condition:
    any of them
}