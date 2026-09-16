rule TTP_XOR_WriteProcessMemory_0ced {
  strings:
    $key_0ced = { 5b 9f [2] 69 bd [2] 6f 88 [2] 41 88 [2] 7e 94 }

  condition:
    any of them
}