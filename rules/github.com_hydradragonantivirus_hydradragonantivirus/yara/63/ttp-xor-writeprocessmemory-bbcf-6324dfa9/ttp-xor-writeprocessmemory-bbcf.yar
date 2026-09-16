rule TTP_XOR_WriteProcessMemory_bbcf {
  strings:
    $key_bbcf = { ec bd [2] de 9f [2] d8 aa [2] f6 aa [2] c9 b6 }

  condition:
    any of them
}