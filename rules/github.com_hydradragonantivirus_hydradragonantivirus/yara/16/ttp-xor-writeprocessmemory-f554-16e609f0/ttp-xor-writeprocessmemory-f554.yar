rule TTP_XOR_WriteProcessMemory_f554 {
  strings:
    $key_f554 = { a2 26 [2] 90 04 [2] 96 31 [2] b8 31 [2] 87 2d }

  condition:
    any of them
}