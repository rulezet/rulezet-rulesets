rule TTP_XOR_WriteProcessMemory_6ecf {
  strings:
    $key_6ecf = { 39 bd [2] 0b 9f [2] 0d aa [2] 23 aa [2] 1c b6 }

  condition:
    any of them
}