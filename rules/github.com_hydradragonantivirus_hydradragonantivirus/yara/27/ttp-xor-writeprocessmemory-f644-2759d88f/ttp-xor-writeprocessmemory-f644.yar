rule TTP_XOR_WriteProcessMemory_f644 {
  strings:
    $key_f644 = { a1 36 [2] 93 14 [2] 95 21 [2] bb 21 [2] 84 3d }

  condition:
    any of them
}