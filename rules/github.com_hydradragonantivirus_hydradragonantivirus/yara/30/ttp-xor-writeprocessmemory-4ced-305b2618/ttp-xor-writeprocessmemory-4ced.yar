rule TTP_XOR_WriteProcessMemory_4ced {
  strings:
    $key_4ced = { 1b 9f [2] 29 bd [2] 2f 88 [2] 01 88 [2] 3e 94 }

  condition:
    any of them
}