rule TTP_XOR_WriteProcessMemory_fcd2 {
  strings:
    $key_fcd2 = { ab a0 [2] 99 82 [2] 9f b7 [2] b1 b7 [2] 8e ab }

  condition:
    any of them
}