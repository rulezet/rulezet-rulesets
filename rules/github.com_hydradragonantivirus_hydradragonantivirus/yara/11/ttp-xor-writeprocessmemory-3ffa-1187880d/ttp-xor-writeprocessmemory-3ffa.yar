rule TTP_XOR_WriteProcessMemory_3ffa {
  strings:
    $key_3ffa = { 68 88 [2] 5a aa [2] 5c 9f [2] 72 9f [2] 4d 83 }

  condition:
    any of them
}