rule TTP_XOR_WriteProcessMemory_6dfa {
  strings:
    $key_6dfa = { 3a 88 [2] 08 aa [2] 0e 9f [2] 20 9f [2] 1f 83 }

  condition:
    any of them
}