rule TTP_XOR_WriteProcessMemory_3af4 {
  strings:
    $key_3af4 = { 6d 86 [2] 5f a4 [2] 59 91 [2] 77 91 [2] 48 8d }

  condition:
    any of them
}