rule TTP_XOR_WriteProcessMemory_06a2 {
  strings:
    $key_06a2 = { 51 d0 [2] 63 f2 [2] 65 c7 [2] 4b c7 [2] 74 db }

  condition:
    any of them
}