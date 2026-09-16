rule TTP_XOR_WriteProcessMemory_da8c {
  strings:
    $key_da8c = { 8d fe [2] bf dc [2] b9 e9 [2] 97 e9 [2] a8 f5 }

  condition:
    any of them
}