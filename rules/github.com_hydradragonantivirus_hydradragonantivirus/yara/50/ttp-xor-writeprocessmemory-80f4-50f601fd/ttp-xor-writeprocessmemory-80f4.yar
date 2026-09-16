rule TTP_XOR_WriteProcessMemory_80f4 {
  strings:
    $key_80f4 = { d7 86 [2] e5 a4 [2] e3 91 [2] cd 91 [2] f2 8d }

  condition:
    any of them
}