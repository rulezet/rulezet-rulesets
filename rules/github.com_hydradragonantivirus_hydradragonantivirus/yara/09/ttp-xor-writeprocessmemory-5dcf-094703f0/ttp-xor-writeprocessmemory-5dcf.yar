rule TTP_XOR_WriteProcessMemory_5dcf {
  strings:
    $key_5dcf = { 0a bd [2] 38 9f [2] 3e aa [2] 10 aa [2] 2f b6 }

  condition:
    any of them
}