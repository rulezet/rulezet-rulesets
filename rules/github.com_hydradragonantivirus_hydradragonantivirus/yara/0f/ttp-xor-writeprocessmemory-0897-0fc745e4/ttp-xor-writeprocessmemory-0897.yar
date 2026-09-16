rule TTP_XOR_WriteProcessMemory_0897 {
  strings:
    $key_0897 = { 5f e5 [2] 6d c7 [2] 6b f2 [2] 45 f2 [2] 7a ee }

  condition:
    any of them
}