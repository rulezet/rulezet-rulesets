rule TTP_XOR_WriteProcessMemory_2dcf {
  strings:
    $key_2dcf = { 7a bd [2] 48 9f [2] 4e aa [2] 60 aa [2] 5f b6 }

  condition:
    any of them
}