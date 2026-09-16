rule TTP_XOR_WriteProcessMemory_bfcf {
  strings:
    $key_bfcf = { e8 bd [2] da 9f [2] dc aa [2] f2 aa [2] cd b6 }

  condition:
    any of them
}