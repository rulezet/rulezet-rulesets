rule TTP_XOR_WriteProcessMemory_3ad3 {
  strings:
    $key_3ad3 = { 6d a1 [2] 5f 83 [2] 59 b6 [2] 77 b6 [2] 48 aa }

  condition:
    any of them
}