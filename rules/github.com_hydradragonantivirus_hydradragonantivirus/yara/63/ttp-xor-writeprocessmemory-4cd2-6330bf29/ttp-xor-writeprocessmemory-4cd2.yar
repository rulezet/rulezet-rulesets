rule TTP_XOR_WriteProcessMemory_4cd2 {
  strings:
    $key_4cd2 = { 1b a0 [2] 29 82 [2] 2f b7 [2] 01 b7 [2] 3e ab }

  condition:
    any of them
}