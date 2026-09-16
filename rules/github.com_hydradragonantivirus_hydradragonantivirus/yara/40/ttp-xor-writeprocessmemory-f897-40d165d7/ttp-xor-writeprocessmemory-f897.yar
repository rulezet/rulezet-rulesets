rule TTP_XOR_WriteProcessMemory_f897 {
  strings:
    $key_f897 = { af e5 [2] 9d c7 [2] 9b f2 [2] b5 f2 [2] 8a ee }

  condition:
    any of them
}