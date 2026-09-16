rule TTP_XOR_WriteProcessMemory_6897 {
  strings:
    $key_6897 = { 3f e5 [2] 0d c7 [2] 0b f2 [2] 25 f2 [2] 1a ee }

  condition:
    any of them
}