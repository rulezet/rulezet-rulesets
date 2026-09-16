rule TTP_XOR_WriteProcessMemory_3ae3 {
  strings:
    $key_3ae3 = { 6d 91 [2] 5f b3 [2] 59 86 [2] 77 86 [2] 48 9a }

  condition:
    any of them
}