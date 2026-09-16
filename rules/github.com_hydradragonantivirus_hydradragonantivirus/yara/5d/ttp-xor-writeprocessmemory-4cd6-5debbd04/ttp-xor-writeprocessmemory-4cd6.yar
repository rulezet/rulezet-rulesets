rule TTP_XOR_WriteProcessMemory_4cd6 {
  strings:
    $key_4cd6 = { 1b a4 [2] 29 86 [2] 2f b3 [2] 01 b3 [2] 3e af }

  condition:
    any of them
}