rule TTP_XOR_WriteProcessMemory_0c36 {
  strings:
    $key_0c36 = { 5b 44 [2] 69 66 [2] 6f 53 [2] 41 53 [2] 7e 4f }

  condition:
    any of them
}