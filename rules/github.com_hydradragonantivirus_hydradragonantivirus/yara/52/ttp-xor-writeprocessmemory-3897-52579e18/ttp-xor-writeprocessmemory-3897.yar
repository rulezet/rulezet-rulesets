rule TTP_XOR_WriteProcessMemory_3897 {
  strings:
    $key_3897 = { 6f e5 [2] 5d c7 [2] 5b f2 [2] 75 f2 [2] 4a ee }

  condition:
    any of them
}