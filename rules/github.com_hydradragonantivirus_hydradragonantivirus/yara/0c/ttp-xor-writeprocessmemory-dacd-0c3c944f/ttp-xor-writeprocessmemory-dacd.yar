rule TTP_XOR_WriteProcessMemory_dacd {
  strings:
    $key_dacd = { 8d bf [2] bf 9d [2] b9 a8 [2] 97 a8 [2] a8 b4 }

  condition:
    any of them
}