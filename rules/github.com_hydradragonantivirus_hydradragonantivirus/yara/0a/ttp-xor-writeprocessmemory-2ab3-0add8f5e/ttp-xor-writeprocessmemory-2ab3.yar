rule TTP_XOR_WriteProcessMemory_2ab3 {
  strings:
    $key_2ab3 = { 7d c1 [2] 4f e3 [2] 49 d6 [2] 67 d6 [2] 58 ca }

  condition:
    any of them
}