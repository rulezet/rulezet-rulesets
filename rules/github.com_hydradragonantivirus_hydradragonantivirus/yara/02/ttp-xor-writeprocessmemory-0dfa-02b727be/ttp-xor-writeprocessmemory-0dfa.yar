rule TTP_XOR_WriteProcessMemory_0dfa {
  strings:
    $key_0dfa = { 5a 88 [2] 68 aa [2] 6e 9f [2] 40 9f [2] 7f 83 }

  condition:
    any of them
}