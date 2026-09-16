rule TTP_XOR_WriteProcessMemory_4ccf {
  strings:
    $key_4ccf = { 1b bd [2] 29 9f [2] 2f aa [2] 01 aa [2] 3e b6 }

  condition:
    any of them
}