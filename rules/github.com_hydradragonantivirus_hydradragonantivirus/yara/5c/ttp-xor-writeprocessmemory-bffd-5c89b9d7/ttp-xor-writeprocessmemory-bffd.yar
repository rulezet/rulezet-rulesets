rule TTP_XOR_WriteProcessMemory_bffd {
  strings:
    $key_bffd = { e8 8f [2] da ad [2] dc 98 [2] f2 98 [2] cd 84 }

  condition:
    any of them
}