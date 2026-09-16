rule TTP_XOR_WriteProcessMemory_7bed {
  strings:
    $key_7bed = { 2c 9f [2] 1e bd [2] 18 88 [2] 36 88 [2] 09 94 }

  condition:
    any of them
}