rule TTP_XOR_WriteProcessMemory_0cea {
  strings:
    $key_0cea = { 5b 98 [2] 69 ba [2] 6f 8f [2] 41 8f [2] 7e 93 }

  condition:
    any of them
}