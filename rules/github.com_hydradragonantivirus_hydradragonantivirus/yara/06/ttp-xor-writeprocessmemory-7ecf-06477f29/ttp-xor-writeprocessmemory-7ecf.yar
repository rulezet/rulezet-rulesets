rule TTP_XOR_WriteProcessMemory_7ecf {
  strings:
    $key_7ecf = { 29 bd [2] 1b 9f [2] 1d aa [2] 33 aa [2] 0c b6 }

  condition:
    any of them
}