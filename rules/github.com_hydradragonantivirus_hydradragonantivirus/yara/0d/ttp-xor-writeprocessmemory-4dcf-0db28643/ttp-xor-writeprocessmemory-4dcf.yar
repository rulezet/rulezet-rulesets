rule TTP_XOR_WriteProcessMemory_4dcf {
  strings:
    $key_4dcf = { 1a bd [2] 28 9f [2] 2e aa [2] 00 aa [2] 3f b6 }

  condition:
    any of them
}