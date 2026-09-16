rule TTP_XOR_WriteProcessMemory_30ea {
  strings:
    $key_30ea = { 67 98 [2] 55 ba [2] 53 8f [2] 7d 8f [2] 42 93 }

  condition:
    any of them
}