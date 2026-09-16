rule TTP_XOR_WriteProcessMemory_2bfa {
  strings:
    $key_2bfa = { 7c 88 [2] 4e aa [2] 48 9f [2] 66 9f [2] 59 83 }

  condition:
    any of them
}