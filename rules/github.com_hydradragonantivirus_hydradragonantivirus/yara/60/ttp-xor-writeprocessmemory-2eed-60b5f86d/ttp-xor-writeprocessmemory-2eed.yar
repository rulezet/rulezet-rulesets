rule TTP_XOR_WriteProcessMemory_2eed {
  strings:
    $key_2eed = { 79 9f [2] 4b bd [2] 4d 88 [2] 63 88 [2] 5c 94 }

  condition:
    any of them
}