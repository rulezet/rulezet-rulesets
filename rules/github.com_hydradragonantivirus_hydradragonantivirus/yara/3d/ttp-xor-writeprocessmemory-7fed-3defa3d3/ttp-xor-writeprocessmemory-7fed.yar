rule TTP_XOR_WriteProcessMemory_7fed {
  strings:
    $key_7fed = { 28 9f [2] 1a bd [2] 1c 88 [2] 32 88 [2] 0d 94 }

  condition:
    any of them
}