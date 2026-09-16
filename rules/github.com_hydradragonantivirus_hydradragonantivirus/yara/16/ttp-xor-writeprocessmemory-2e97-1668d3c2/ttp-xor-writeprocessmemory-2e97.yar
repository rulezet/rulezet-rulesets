rule TTP_XOR_WriteProcessMemory_2e97 {
  strings:
    $key_2e97 = { 79 e5 [2] 4b c7 [2] 4d f2 [2] 63 f2 [2] 5c ee }

  condition:
    any of them
}