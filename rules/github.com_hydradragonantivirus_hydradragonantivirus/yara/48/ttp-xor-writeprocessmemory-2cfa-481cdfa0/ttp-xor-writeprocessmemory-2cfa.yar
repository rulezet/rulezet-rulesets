rule TTP_XOR_WriteProcessMemory_2cfa {
  strings:
    $key_2cfa = { 7b 88 [2] 49 aa [2] 4f 9f [2] 61 9f [2] 5e 83 }

  condition:
    any of them
}