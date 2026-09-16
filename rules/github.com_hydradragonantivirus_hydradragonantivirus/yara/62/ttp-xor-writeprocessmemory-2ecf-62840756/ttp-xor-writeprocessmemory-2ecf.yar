rule TTP_XOR_WriteProcessMemory_2ecf {
  strings:
    $key_2ecf = { 79 bd [2] 4b 9f [2] 4d aa [2] 63 aa [2] 5c b6 }

  condition:
    any of them
}