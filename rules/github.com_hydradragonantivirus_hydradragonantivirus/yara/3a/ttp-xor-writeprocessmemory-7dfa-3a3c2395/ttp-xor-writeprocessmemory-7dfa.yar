rule TTP_XOR_WriteProcessMemory_7dfa {
  strings:
    $key_7dfa = { 2a 88 [2] 18 aa [2] 1e 9f [2] 30 9f [2] 0f 83 }

  condition:
    any of them
}