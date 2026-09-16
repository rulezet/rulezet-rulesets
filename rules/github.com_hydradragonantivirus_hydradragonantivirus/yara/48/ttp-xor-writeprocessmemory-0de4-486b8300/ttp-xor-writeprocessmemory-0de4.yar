rule TTP_XOR_WriteProcessMemory_0de4 {
  strings:
    $key_0de4 = { 5a 96 [2] 68 b4 [2] 6e 81 [2] 40 81 [2] 7f 9d }

  condition:
    any of them
}