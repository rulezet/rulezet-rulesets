rule TTP_XOR_WriteProcessMemory_3acf {
  strings:
    $key_3acf = { 6d bd [2] 5f 9f [2] 59 aa [2] 77 aa [2] 48 b6 }

  condition:
    any of them
}