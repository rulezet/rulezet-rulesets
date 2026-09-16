rule TTP_XOR_WriteProcessMemory_6ccf {
  strings:
    $key_6ccf = { 3b bd [2] 09 9f [2] 0f aa [2] 21 aa [2] 1e b6 }

  condition:
    any of them
}