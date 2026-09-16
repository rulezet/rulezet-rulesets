rule TTP_XOR_WriteProcessMemory_2bed {
  strings:
    $key_2bed = { 7c 9f [2] 4e bd [2] 48 88 [2] 66 88 [2] 59 94 }

  condition:
    any of them
}