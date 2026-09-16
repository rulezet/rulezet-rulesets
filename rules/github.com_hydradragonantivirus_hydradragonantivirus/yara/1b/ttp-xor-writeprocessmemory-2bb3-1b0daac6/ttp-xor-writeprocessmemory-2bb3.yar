rule TTP_XOR_WriteProcessMemory_2bb3 {
  strings:
    $key_2bb3 = { 7c c1 [2] 4e e3 [2] 48 d6 [2] 66 d6 [2] 59 ca }

  condition:
    any of them
}