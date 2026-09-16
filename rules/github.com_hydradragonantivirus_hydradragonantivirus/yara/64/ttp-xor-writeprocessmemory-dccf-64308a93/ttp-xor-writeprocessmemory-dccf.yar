rule TTP_XOR_WriteProcessMemory_dccf {
  strings:
    $key_dccf = { 8b bd [2] b9 9f [2] bf aa [2] 91 aa [2] ae b6 }

  condition:
    any of them
}