rule TTP_XOR_WriteProcessMemory_1cfa {
  strings:
    $key_1cfa = { 4b 88 [2] 79 aa [2] 7f 9f [2] 51 9f [2] 6e 83 }

  condition:
    any of them
}