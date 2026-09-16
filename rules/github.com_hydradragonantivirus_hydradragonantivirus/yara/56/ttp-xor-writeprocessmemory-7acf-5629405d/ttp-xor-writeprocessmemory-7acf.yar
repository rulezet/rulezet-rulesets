rule TTP_XOR_WriteProcessMemory_7acf {
  strings:
    $key_7acf = { 2d bd [2] 1f 9f [2] 19 aa [2] 37 aa [2] 08 b6 }

  condition:
    any of them
}