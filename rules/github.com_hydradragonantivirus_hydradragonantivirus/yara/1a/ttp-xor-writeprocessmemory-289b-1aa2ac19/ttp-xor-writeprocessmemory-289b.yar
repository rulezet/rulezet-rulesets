rule TTP_XOR_WriteProcessMemory_289b {
  strings:
    $key_289b = { 7f e9 [2] 4d cb [2] 4b fe [2] 65 fe [2] 5a e2 }

  condition:
    any of them
}