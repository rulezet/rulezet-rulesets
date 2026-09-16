rule TTP_XOR_WriteProcessMemory_03ea {
  strings:
    $key_03ea = { 54 98 [2] 66 ba [2] 60 8f [2] 4e 8f [2] 71 93 }

  condition:
    any of them
}