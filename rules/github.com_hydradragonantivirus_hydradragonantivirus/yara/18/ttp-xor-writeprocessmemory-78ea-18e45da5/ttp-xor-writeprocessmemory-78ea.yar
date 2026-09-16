rule TTP_XOR_WriteProcessMemory_78ea {
  strings:
    $key_78ea = { 2f 98 [2] 1d ba [2] 1b 8f [2] 35 8f [2] 0a 93 }

  condition:
    any of them
}