rule TTP_XOR_WriteProcessMemory_1fed {
  strings:
    $key_1fed = { 48 9f [2] 7a bd [2] 7c 88 [2] 52 88 [2] 6d 94 }

  condition:
    any of them
}