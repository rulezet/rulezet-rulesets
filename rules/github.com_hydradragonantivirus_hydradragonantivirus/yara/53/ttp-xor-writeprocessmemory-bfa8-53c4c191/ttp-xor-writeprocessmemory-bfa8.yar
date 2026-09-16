rule TTP_XOR_WriteProcessMemory_bfa8 {
  strings:
    $key_bfa8 = { e8 da [2] da f8 [2] dc cd [2] f2 cd [2] cd d1 }

  condition:
    any of them
}