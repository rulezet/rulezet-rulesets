rule TTP_XOR_WriteProcessMemory_7eed {
  strings:
    $key_7eed = { 29 9f [2] 1b bd [2] 1d 88 [2] 33 88 [2] 0c 94 }

  condition:
    any of them
}