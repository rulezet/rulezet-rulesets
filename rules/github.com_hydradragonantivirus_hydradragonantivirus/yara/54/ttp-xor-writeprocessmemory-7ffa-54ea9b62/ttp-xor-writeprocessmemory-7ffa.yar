rule TTP_XOR_WriteProcessMemory_7ffa {
  strings:
    $key_7ffa = { 28 88 [2] 1a aa [2] 1c 9f [2] 32 9f [2] 0d 83 }

  condition:
    any of them
}