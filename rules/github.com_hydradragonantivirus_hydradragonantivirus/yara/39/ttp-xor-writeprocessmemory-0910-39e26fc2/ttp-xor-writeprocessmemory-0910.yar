rule TTP_XOR_WriteProcessMemory_0910 {
  strings:
    $key_0910 = { 5e 62 [2] 6c 40 [2] 6a 75 [2] 44 75 [2] 7b 69 }

  condition:
    any of them
}