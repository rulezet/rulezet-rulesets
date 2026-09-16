rule TTP_XOR_WriteProcessMemory_04a2 {
  strings:
    $key_04a2 = { 53 d0 [2] 61 f2 [2] 67 c7 [2] 49 c7 [2] 76 db }

  condition:
    any of them
}