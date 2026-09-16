rule TTP_XOR_WriteProcessMemory_4fed {
  strings:
    $key_4fed = { 18 9f [2] 2a bd [2] 2c 88 [2] 02 88 [2] 3d 94 }

  condition:
    any of them
}