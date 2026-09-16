rule TTP_XOR_WriteProcessMemory_24ea {
  strings:
    $key_24ea = { 73 98 [2] 41 ba [2] 47 8f [2] 69 8f [2] 56 93 }

  condition:
    any of them
}