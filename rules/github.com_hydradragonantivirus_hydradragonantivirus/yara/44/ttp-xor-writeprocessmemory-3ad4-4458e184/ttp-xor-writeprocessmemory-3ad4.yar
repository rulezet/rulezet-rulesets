rule TTP_XOR_WriteProcessMemory_3ad4 {
  strings:
    $key_3ad4 = { 6d a6 [2] 5f 84 [2] 59 b1 [2] 77 b1 [2] 48 ad }

  condition:
    any of them
}