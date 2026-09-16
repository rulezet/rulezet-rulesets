rule TTP_XOR_WriteProcessMemory_0ecf {
  strings:
    $key_0ecf = { 59 bd [2] 6b 9f [2] 6d aa [2] 43 aa [2] 7c b6 }

  condition:
    any of them
}