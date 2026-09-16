rule TTP_XOR_WriteProcessMemory_2acf {
  strings:
    $key_2acf = { 7d bd [2] 4f 9f [2] 49 aa [2] 67 aa [2] 58 b6 }

  condition:
    any of them
}