rule TTP_XOR_WriteProcessMemory_1ccf {
  strings:
    $key_1ccf = { 4b bd [2] 79 9f [2] 7f aa [2] 51 aa [2] 6e b6 }

  condition:
    any of them
}