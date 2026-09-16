rule TTP_XOR_WriteProcessMemory_cd9c {
  strings:
    $key_cd9c = { 9a ee [2] a8 cc [2] ae f9 [2] 80 f9 [2] bf e5 }

  condition:
    any of them
}