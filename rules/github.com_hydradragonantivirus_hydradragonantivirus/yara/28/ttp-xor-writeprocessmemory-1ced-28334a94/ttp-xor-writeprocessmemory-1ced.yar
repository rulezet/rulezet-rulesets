rule TTP_XOR_WriteProcessMemory_1ced {
  strings:
    $key_1ced = { 4b 9f [2] 79 bd [2] 7f 88 [2] 51 88 [2] 6e 94 }

  condition:
    any of them
}