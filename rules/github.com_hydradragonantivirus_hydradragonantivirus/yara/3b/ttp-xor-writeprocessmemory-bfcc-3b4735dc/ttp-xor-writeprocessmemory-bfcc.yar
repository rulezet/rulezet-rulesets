rule TTP_XOR_WriteProcessMemory_bfcc {
  strings:
    $key_bfcc = { e8 be [2] da 9c [2] dc a9 [2] f2 a9 [2] cd b5 }

  condition:
    any of them
}