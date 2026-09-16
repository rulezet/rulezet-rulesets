rule TTP_XOR_WriteProcessMemory_fecf {
  strings:
    $key_fecf = { a9 bd [2] 9b 9f [2] 9d aa [2] b3 aa [2] 8c b6 }

  condition:
    any of them
}