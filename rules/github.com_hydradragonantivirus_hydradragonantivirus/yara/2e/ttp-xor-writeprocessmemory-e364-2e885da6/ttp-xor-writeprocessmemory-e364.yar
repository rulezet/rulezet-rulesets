rule TTP_XOR_WriteProcessMemory_e364 {
  strings:
    $key_e364 = { b4 16 [2] 86 34 [2] 80 01 [2] ae 01 [2] 91 1d }

  condition:
    any of them
}