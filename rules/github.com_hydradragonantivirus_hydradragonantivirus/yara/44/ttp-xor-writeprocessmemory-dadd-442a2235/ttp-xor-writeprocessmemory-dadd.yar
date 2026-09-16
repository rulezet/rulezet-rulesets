rule TTP_XOR_WriteProcessMemory_dadd {
  strings:
    $key_dadd = { 8d af [2] bf 8d [2] b9 b8 [2] 97 b8 [2] a8 a4 }

  condition:
    any of them
}