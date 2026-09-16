rule TTP_XOR_WriteProcessMemory_28ac {
  strings:
    $key_28ac = { 7f de [2] 4d fc [2] 4b c9 [2] 65 c9 [2] 5a d5 }

  condition:
    any of them
}