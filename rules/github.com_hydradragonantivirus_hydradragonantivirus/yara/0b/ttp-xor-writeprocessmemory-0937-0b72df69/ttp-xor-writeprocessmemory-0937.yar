rule TTP_XOR_WriteProcessMemory_0937 {
  strings:
    $key_0937 = { 5e 45 [2] 6c 67 [2] 6a 52 [2] 44 52 [2] 7b 4e }

  condition:
    any of them
}