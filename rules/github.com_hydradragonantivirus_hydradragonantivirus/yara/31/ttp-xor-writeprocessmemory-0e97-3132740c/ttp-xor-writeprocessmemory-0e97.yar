rule TTP_XOR_WriteProcessMemory_0e97 {
  strings:
    $key_0e97 = { 59 e5 [2] 6b c7 [2] 6d f2 [2] 43 f2 [2] 7c ee }

  condition:
    any of them
}