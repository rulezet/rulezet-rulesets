rule TTP_XOR_WriteProcessMemory_0922 {
  strings:
    $key_0922 = { 5e 50 [2] 6c 72 [2] 6a 47 [2] 44 47 [2] 7b 5b }

  condition:
    any of them
}