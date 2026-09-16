rule TTP_XOR_WriteProcessMemory_f8ac {
  strings:
    $key_f8ac = { af de [2] 9d fc [2] 9b c9 [2] b5 c9 [2] 8a d5 }

  condition:
    any of them
}