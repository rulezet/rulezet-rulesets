rule TTP_XOR_WriteProcessMemory_1897 {
  strings:
    $key_1897 = { 4f e5 [2] 7d c7 [2] 7b f2 [2] 55 f2 [2] 6a ee }

  condition:
    any of them
}