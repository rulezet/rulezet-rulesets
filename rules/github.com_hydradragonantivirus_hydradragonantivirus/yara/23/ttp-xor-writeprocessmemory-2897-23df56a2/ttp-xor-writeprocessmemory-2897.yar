rule TTP_XOR_WriteProcessMemory_2897 {
  strings:
    $key_2897 = { 7f e5 [2] 4d c7 [2] 4b f2 [2] 65 f2 [2] 5a ee }

  condition:
    any of them
}