rule TTP_XOR_WriteProcessMemory_7cea {
  strings:
    $key_7cea = { 2b 98 [2] 19 ba [2] 1f 8f [2] 31 8f [2] 0e 93 }

  condition:
    any of them
}