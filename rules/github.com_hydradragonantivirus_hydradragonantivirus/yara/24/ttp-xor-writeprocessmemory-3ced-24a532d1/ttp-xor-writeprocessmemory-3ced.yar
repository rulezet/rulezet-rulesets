rule TTP_XOR_WriteProcessMemory_3ced {
  strings:
    $key_3ced = { 6b 9f [2] 59 bd [2] 5f 88 [2] 71 88 [2] 4e 94 }

  condition:
    any of them
}