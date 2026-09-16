rule TTP_XOR_WriteProcessMemory_fad2 {
  strings:
    $key_fad2 = { ad a0 [2] 9f 82 [2] 99 b7 [2] b7 b7 [2] 88 ab }

  condition:
    any of them
}