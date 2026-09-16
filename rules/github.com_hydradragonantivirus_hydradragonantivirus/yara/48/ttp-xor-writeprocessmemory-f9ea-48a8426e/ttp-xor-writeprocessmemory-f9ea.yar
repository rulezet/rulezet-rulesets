rule TTP_XOR_WriteProcessMemory_f9ea {
  strings:
    $key_f9ea = { ae 98 [2] 9c ba [2] 9a 8f [2] b4 8f [2] 8b 93 }

  condition:
    any of them
}