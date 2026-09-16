rule TTP_XOR_WriteProcessMemory_5acf {
  strings:
    $key_5acf = { 0d bd [2] 3f 9f [2] 39 aa [2] 17 aa [2] 28 b6 }

  condition:
    any of them
}