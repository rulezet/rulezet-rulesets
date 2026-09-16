rule TTP_XOR_WriteProcessMemory_151a {
  strings:
    $key_151a = { 42 68 [2] 70 4a [2] 76 7f [2] 58 7f [2] 67 63 }

  condition:
    any of them
}