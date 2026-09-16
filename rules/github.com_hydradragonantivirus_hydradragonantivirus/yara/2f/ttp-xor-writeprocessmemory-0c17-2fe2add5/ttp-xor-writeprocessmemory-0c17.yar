rule TTP_XOR_WriteProcessMemory_0c17 {
  strings:
    $key_0c17 = { 5b 65 [2] 69 47 [2] 6f 72 [2] 41 72 [2] 7e 6e }

  condition:
    any of them
}