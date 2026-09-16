rule TTP_XOR_WriteProcessMemory_0ffa {
  strings:
    $key_0ffa = { 58 88 [2] 6a aa [2] 6c 9f [2] 42 9f [2] 7d 83 }

  condition:
    any of them
}