rule TTP_XOR_WriteProcessMemory_7e97 {
  strings:
    $key_7e97 = { 29 e5 [2] 1b c7 [2] 1d f2 [2] 33 f2 [2] 0c ee }

  condition:
    any of them
}