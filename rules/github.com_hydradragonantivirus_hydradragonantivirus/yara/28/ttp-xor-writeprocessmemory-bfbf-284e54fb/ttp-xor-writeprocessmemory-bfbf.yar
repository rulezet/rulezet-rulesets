rule TTP_XOR_WriteProcessMemory_bfbf {
  strings:
    $key_bfbf = { e8 cd [2] da ef [2] dc da [2] f2 da [2] cd c6 }

  condition:
    any of them
}