rule TTP_XOR_WriteProcessMemory_2fed {
  strings:
    $key_2fed = { 78 9f [2] 4a bd [2] 4c 88 [2] 62 88 [2] 5d 94 }

  condition:
    any of them
}