rule TTP_XOR_WriteProcessMemory_06ea {
  strings:
    $key_06ea = { 51 98 [2] 63 ba [2] 65 8f [2] 4b 8f [2] 74 93 }

  condition:
    any of them
}