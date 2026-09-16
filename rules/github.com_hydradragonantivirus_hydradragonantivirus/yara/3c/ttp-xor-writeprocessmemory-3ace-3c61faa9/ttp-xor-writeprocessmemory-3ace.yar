rule TTP_XOR_WriteProcessMemory_3ace {
  strings:
    $key_3ace = { 6d bc [2] 5f 9e [2] 59 ab [2] 77 ab [2] 48 b7 }

  condition:
    any of them
}