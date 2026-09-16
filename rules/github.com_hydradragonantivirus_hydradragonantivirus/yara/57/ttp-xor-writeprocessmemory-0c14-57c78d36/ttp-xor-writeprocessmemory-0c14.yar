rule TTP_XOR_WriteProcessMemory_0c14 {
  strings:
    $key_0c14 = { 5b 66 [2] 69 44 [2] 6f 71 [2] 41 71 [2] 7e 6d }

  condition:
    any of them
}