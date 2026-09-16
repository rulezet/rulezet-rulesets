rule TTP_XOR_WriteProcessMemory_3ecf {
  strings:
    $key_3ecf = { 69 bd [2] 5b 9f [2] 5d aa [2] 73 aa [2] 4c b6 }

  condition:
    any of them
}