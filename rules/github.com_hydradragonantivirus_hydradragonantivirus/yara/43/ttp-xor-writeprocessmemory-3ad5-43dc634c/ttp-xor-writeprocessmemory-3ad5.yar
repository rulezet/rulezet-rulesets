rule TTP_XOR_WriteProcessMemory_3ad5 {
  strings:
    $key_3ad5 = { 6d a7 [2] 5f 85 [2] 59 b0 [2] 77 b0 [2] 48 ac }

  condition:
    any of them
}