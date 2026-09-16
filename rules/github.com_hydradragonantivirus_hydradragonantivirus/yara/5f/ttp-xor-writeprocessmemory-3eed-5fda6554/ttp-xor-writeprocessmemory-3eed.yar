rule TTP_XOR_WriteProcessMemory_3eed {
  strings:
    $key_3eed = { 69 9f [2] 5b bd [2] 5d 88 [2] 73 88 [2] 4c 94 }

  condition:
    any of them
}