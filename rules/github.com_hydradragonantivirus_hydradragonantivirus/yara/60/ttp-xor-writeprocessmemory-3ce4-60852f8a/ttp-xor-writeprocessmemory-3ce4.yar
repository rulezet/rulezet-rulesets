rule TTP_XOR_WriteProcessMemory_3ce4 {
  strings:
    $key_3ce4 = { 6b 96 [2] 59 b4 [2] 5f 81 [2] 71 81 [2] 4e 9d }

  condition:
    any of them
}