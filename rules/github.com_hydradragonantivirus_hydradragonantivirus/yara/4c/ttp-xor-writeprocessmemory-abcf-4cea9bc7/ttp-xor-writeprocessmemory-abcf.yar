rule TTP_XOR_WriteProcessMemory_abcf {
  strings:
    $key_abcf = { fc bd [2] ce 9f [2] c8 aa [2] e6 aa [2] d9 b6 }

  condition:
    any of them
}