rule TTP_XOR_WriteProcessMemory_2eea {
  strings:
    $key_2eea = { 79 98 [2] 4b ba [2] 4d 8f [2] 63 8f [2] 5c 93 }

  condition:
    any of them
}