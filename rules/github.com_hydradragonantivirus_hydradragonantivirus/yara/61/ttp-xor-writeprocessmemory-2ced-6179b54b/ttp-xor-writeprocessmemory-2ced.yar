rule TTP_XOR_WriteProcessMemory_2ced {
  strings:
    $key_2ced = { 7b 9f [2] 49 bd [2] 4f 88 [2] 61 88 [2] 5e 94 }

  condition:
    any of them
}